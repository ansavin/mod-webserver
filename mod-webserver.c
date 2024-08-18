#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/inet.h>
#include <linux/version.h>
#include <linux/moduleparam.h>
#include <net/netns/generic.h>

#include <net/tcp.h>
#include <net/sock.h>

#ifdef DEBUG
#define dprintk(X...) printk(KERN_INFO X)
#else
#define dprintk(X...)                                                          \
	do {                                                                   \
	} while (0)
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrei Savin <andrei.v.savin@gmail.com>");
MODULE_DESCRIPTION("Stub web server in kernel space");
MODULE_VERSION("2.0");

static char *port = "2000";
static char *host = "0.0.0.0";
unsigned int netns_subsys_id;
static struct kset *server_kset;
static struct kobject *server_netns_kobj;

struct server_data {
	struct kobject kobject;
	struct net *net;
	int status;
};

struct pernet_server_net {
	struct work_struct server_accept_conn;
	struct socket *server_sock;
	struct server_data *data;
};

struct client_work_queue {
	struct work_struct client_work;
	struct socket *client_sock;
};

module_param(port, charp, 0);
MODULE_PARM_DESC(port, "Webserver port");
module_param(host, charp, 0);
MODULE_PARM_DESC(host, "Webserver host");

void server_stop(struct pernet_server_net *pernet);
struct server_data *pernet_data_alloc(struct net *net);
void netns_subsys_destroy(struct net *net);

static void client_handler(struct work_struct *w)
{
	u64 addr;
	int ret;
	struct page *page;
	struct client_work_queue *queue;
	char *msg = "HTTP/1.1 200 OK\n\nPONG\n";
	int flags = 0;
	int left = strlen(msg);
	int offset = 0;

	pr_info("accepted incoming connection\n");

	queue = container_of(w, struct client_work_queue, client_work);
	if (!queue) {
		pr_err("can't get client work queue\n");
		return;
	}

	addr = __get_free_page(GFP_KERNEL);
	if (!addr) {
		pr_err("out of memory error\n");
		goto err;
	}

	memcpy((u64 *)addr, msg, strlen(msg));

	page = virt_to_page(addr);
	if (!page) {
		pr_err("can't get page\n");
		goto err_page;
	}

	ret = kernel_sendpage(queue->client_sock, page, offset, left, flags);
	if (ret < 0)
		pr_err("can't send page to client: %d\n", ret);

err_page:
	put_page(page);
err:
	sock_release(queue->client_sock);
	kfree(queue);
}

static int server_tcp_alloc_queue(struct socket *client_sock)
{
	struct client_work_queue *queue;

	queue = kzalloc(sizeof(*queue), GFP_KERNEL);
	if (!queue)
		return -ENOMEM;

	dprintk("server_tcp_alloc_queue in %u net ns\n", sock_net(client_sock->sk)->ns.inum);
	INIT_WORK(&queue->client_work, client_handler);
	queue->client_sock = client_sock;
	schedule_work(&queue->client_work);

	return 0;
}

static void server_listener(struct work_struct *w)
{
	struct pernet_server_net *pernet;
	struct socket *client_sock;
	int ret;

	pernet = container_of(w, struct pernet_server_net, server_accept_conn);

	while (true) {
		dprintk("server_listener loop in %u net ns\n", pernet->server_data->net->ns.inum);
		ret = kernel_accept(pernet->server_sock, &client_sock,
				    O_NONBLOCK);
		if (ret < 0) {
			if (ret != -EAGAIN)
				pr_warn("failed to accept err=%d\n", ret);
			return;
		}
		ret = server_tcp_alloc_queue(client_sock);
		if (ret) {
			pr_err("failed to allocate queue\n");
			sock_release(client_sock);
		}
	}
}

static void server_tcp_listen_data_ready(struct sock *sk)
{
	struct pernet_server_net *pernet;

	read_lock_bh(&sk->sk_callback_lock);
	pernet = sk->sk_user_data;

	if (sk->sk_state == TCP_LISTEN)
		schedule_work(&pernet->server_accept_conn);

	dprintk("server_tcp_listen_data_ready in %u net ns\n", pernet->server_data->net->ns.inum);

	read_unlock_bh(&sk->sk_callback_lock);
}

static int server_init(struct net *net)
{
	int ret;
	struct sockaddr_storage server_addr;
	__kernel_sa_family_t af = AF_INET;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0))
	int opt = 1;
#endif
	struct pernet_server_net *pernet;

	pernet = net_generic(net, netns_subsys_id);

	ret = inet_pton_with_scope(net, af, host, port, &server_addr);
	if (ret) {
		pr_err("malformed ip/port passed: %s:%s\n", host, port);
		goto err_port;
	}

	ret = __sock_create(net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
			    &pernet->server_sock, 1);
	if (ret) {
		pr_err("failed to create a socket\n");
		goto err_port;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
	sock_set_reuseaddr(pernet->server_sock->sk);
	tcp_sock_set_nodelay(pernet->server_sock->sk);
#else
	ret = kernel_setsockopt(pernet->server_sock, SOL_SOCKET, SO_REUSEADDR,
				(char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set SO_REUSEADDR sock opt %d\n", ret);
		goto err_sock;
	}

	ret = kernel_setsockopt(pernet->server_sock, IPPROTO_TCP, TCP_NODELAY,
				(char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set TCP_NODELAY sock opt %d\n", ret);
		goto err_sock;
	}
#endif

	ret = kernel_bind(pernet->server_sock, (struct sockaddr *)&server_addr,
			  sizeof(server_addr));
	if (ret) {
		pr_err("failed to bind port socket\n");
		goto err_sock;
	}

	ret = kernel_listen(pernet->server_sock, 128);
	if (ret) {
		pr_err("failed to listen on port sock\n");
		goto err_sock;
	}

	INIT_WORK(&pernet->server_accept_conn, server_listener);
	pernet->server_sock->sk->sk_user_data = pernet;
	pernet->server_sock->sk->sk_data_ready = server_tcp_listen_data_ready;

	pr_info("server is listening on %s:%s in %u net ns\n", host, port,
		net->ns.inum);
	return 0;

err_sock:
	sock_release(pernet->server_sock);
	pernet->server_sock = NULL;
err_port:
	return ret;
}

void server_stop(struct pernet_server_net *pernet)
{
	dprintk("%s(%px) in %u net ns\n", __func__, pernet, pernet->server_data->net->ns.inum);

	if (pernet->server_sock) {
		sock_release(pernet->server_sock);
		pernet->server_sock = NULL;
	}

	if (pernet->server_accept_conn.func) {
		flush_work(&pernet->server_accept_conn);
		cancel_work_sync(&pernet->server_accept_conn);
	}
}

static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	struct server_data *c = container_of(kobj, struct server_data, kobject);
	return sysfs_emit(buf, "%i\n", c->status);
}

static ssize_t status_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	int ret;
	struct pernet_server_net *pernet;
	int new_status;

	struct server_data *c = container_of(kobj, struct server_data, kobject);

	dprintk("%s call: in %u net ns\n", __func__, c->net->ns.inum);
	ret = kstrtoint(buf, 10, &new_status);
	if (ret < 0)
		return ret;

	if (!(new_status == 1 || new_status == 0))
		return -EINVAL;

	if (new_status == c->status)
		return count;

	if (new_status == 1) {
		ret = server_init(c->net);
		if (ret < 0) {
			pr_err("failed to start server, aborting\n");
			return -EIO;
		}
	} else if (new_status == 0) {
		pernet = net_generic(c->net, netns_subsys_id);
		server_stop(pernet);
	}

	c->status = new_status;
	return count;
}

static struct kobj_attribute status_attribute =
	__ATTR(status, 0664, status_show, status_store);

static struct attribute *server_attrs[] = {
	&status_attribute.attr,
	NULL, /* need to NULL terminate the list of attributes */
};
ATTRIBUTE_GROUPS(server);

static const void *server_namespace(const struct kobject *kobj)
{
	return container_of(kobj, struct server_data, kobject)->net;
}

static void server_release(struct kobject *kobj)
{
	struct server_data *c = container_of(kobj, struct server_data, kobject);
	dprintk("%s(%px) call: kfree(%px) in %u net ns\n", __func__, kobj, c, c->net->ns.inum);
	kfree(c);
}

static struct kobj_type server_type = {
	.release = server_release,
	.default_groups = server_groups,
	.sysfs_ops = &kobj_sysfs_ops,
	.namespace = server_namespace,
};

struct server_data *pernet_data_alloc(struct net *net)
{
	struct server_data *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (p) {
		p->net = net;
		p->kobject.kset = server_kset;
		if (kobject_init_and_add(&p->kobject, &server_type, server_netns_kobj,
					 "data") == 0) {
			dprintk("%s call: kobject_init_and_add(%px) in %u net ns\n", __func__, &p->kobject, net->ns.inum);
			return p;
					 }
		dprintk("%s call: kobject_put(%px) in %u net ns\n", __func__, &p->kobject, net->ns.inum);
		kobject_put(&p->kobject);
	}
	return NULL;
}

static int netns_subsys_setup(struct net *net)
{
	struct server_data *data;
	struct pernet_server_net *pernet;

	dprintk("%s(%px) in %u net ns\n", __func__, net, net->ns.inum);

	pernet = net_generic(net, netns_subsys_id);

	data = pernet_data_alloc(net);
	if (!data) {
		return -ENOMEM;
	}

	pernet->data = data;

	return 0;
}

void netns_subsys_destroy(struct net *net)
{
	struct pernet_server_net *pernet;
	struct server_data *data;

	pernet = net_generic(net, netns_subsys_id);

	data = pernet->data;

	dprintk("%s: kobject_put(%px) in %u net ns\n", __func__, &data->kobject, net->ns.inum);

	server_stop(pernet);

	kobject_del(&data->kobject);
	kobject_put(&data->kobject);
}

static struct pernet_operations netns_subsys_ops = {
	.init = netns_subsys_setup,
	.exit = netns_subsys_destroy,
	.id = &netns_subsys_id,
	.size = sizeof(struct pernet_server_net),
};

static void server_object_release(struct kobject *kobj)
{
	dprintk("%s(%px)\n", __func__, kobj);
	kfree(kobj);
}

static const struct kobj_ns_type_operations *
server_object_child_ns_type(const struct kobject *kobj)
{
	return &net_ns_type_operations;
}

static struct kobj_type server_object_type = {
	.release = server_object_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.child_ns_type = server_object_child_ns_type,
};


static struct kobject *server_object_alloc(const char *name, struct kset *kset)
{
	struct kobject *kobj;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (kobj) {
		kobj->kset = kset;
		if (kobject_init_and_add(kobj, &server_object_type, NULL,
					 "%s", name) == 0)
			return kobj;
		dprintk("%s: kobject_put(%px)\n", __func__, kobj);
		kobject_put(kobj);
	}
	return NULL;
}

static void remove_kset(void)
{
	kset_unregister(server_kset);
	server_kset = NULL;
}

static void remove_main_kobject(void)
{
	kobject_put(server_netns_kobj);
	server_netns_kobj = NULL;
}

static int __init simple_webserver_lkm_init(void)
{
	int ret;
	pr_info("adding simple web server LKM\n");

	server_kset = kset_create_and_add("webserver", NULL, kernel_kobj);
	if (!server_kset) {
		pr_warn("can't create kset\n");
		return -ENOMEM;
	}

	server_netns_kobj = server_object_alloc("net", server_kset);
	if (!server_netns_kobj) {
		pr_warn("can't create kobject\n");
		remove_kset();
		return -ENOMEM;
	}

	ret = register_pernet_subsys(&netns_subsys_ops);
	if (ret < 0) {
		remove_kset();
		remove_main_kobject();
		pr_err("failed to init pernet subsystem, aborting\n");
	}
	return ret;
}

static void __exit simple_webserver_lkm_exit(void)
{
	unregister_pernet_subsys(&netns_subsys_ops);
	remove_kset();
	remove_main_kobject();
	pr_info("simple web server LKM removed\n");
}

module_init(simple_webserver_lkm_init);
module_exit(simple_webserver_lkm_exit);
