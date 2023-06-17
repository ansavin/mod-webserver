#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/inet.h>
#include <linux/version.h>
#include <linux/moduleparam.h>

#include <net/tcp.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrei Savin <andrei.v.savin@gmail.com>");
MODULE_DESCRIPTION("Stub web server in kernel space");
MODULE_VERSION("1.0");

static struct work_struct server_accept_conn;
static struct socket *server_sock;
static char *port = "2000";
static char *host = "0.0.0.0";

struct client_work_queue {
	struct work_struct client_work;
	struct socket *client_sock;
};

module_param(port, charp, 0);
MODULE_PARM_DESC(port, "Webserver port");
module_param(host, charp, 0);
MODULE_PARM_DESC(host, "Webserver host");

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

	INIT_WORK(&queue->client_work, client_handler);
	queue->client_sock = client_sock;
	schedule_work(&queue->client_work);

	return 0;
}

static void server_listener(struct work_struct *w)
{
	struct socket *client_sock;
	int ret;

	while (true) {
		ret = kernel_accept(server_sock, &client_sock, O_NONBLOCK);
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
	read_lock_bh(&sk->sk_callback_lock);

	if (sk->sk_state == TCP_LISTEN)
		schedule_work(&server_accept_conn);
	read_unlock_bh(&sk->sk_callback_lock);
}

static int server_init(void)
{
	int ret;
	struct sockaddr_storage server_addr;
	__kernel_sa_family_t af = AF_INET;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0))
	int opt = 1;
#endif

	ret = inet_pton_with_scope(&init_net, af, host, port, &server_addr);
	if (ret) {
		pr_err("malformed ip/port passed: %s:%s\n", host, port);
		goto err_port;
	}

	ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &server_sock);
	if (ret) {
		pr_err("failed to create a socket\n");
		goto err_port;
	}

	ret = kernel_bind(server_sock, (struct sockaddr *)&server_addr,
			  sizeof(server_addr));
	if (ret) {
		pr_err("failed to bind port socket\n");
		goto err_sock;
	}

	ret = kernel_listen(server_sock, 128);
	if (ret) {
		pr_err("failed to listen on port sock\n");
		goto err_sock;
	}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
	sock_set_reuseaddr(server_sock->sk);
	tcp_sock_set_nodelay(server_sock->sk);
#else
	ret = kernel_setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR,
				(char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set SO_REUSEADDR sock opt %d\n", ret);
		goto err_sock;
	}

	ret = kernel_setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY,
				(char *)&opt, sizeof(opt));
	if (ret) {
		pr_err("failed to set TCP_NODELAY sock opt %d\n", ret);
		goto err_sock;
	}
#endif

	INIT_WORK(&server_accept_conn, server_listener);
	server_sock->sk->sk_data_ready = server_tcp_listen_data_ready;

	pr_info("server is listening on %s:%s\n", host, port);
	return 0;

err_sock:
	sock_release(server_sock);
	server_sock = NULL;
err_port:
	return ret;
}

static int __init simple_webserver_lkm_init(void)
{
	int ret;
	pr_info("adding simple web server LKM\n");

	ret = server_init();
	if (ret < 0)
		pr_err("failed to init module, aborting\n");

	return ret;
}

static void __exit simple_webserver_lkm_exit(void)
{
	if (server_sock)
		sock_release(server_sock);
	if (server_accept_conn.func) {
		flush_work(&server_accept_conn);
		cancel_work_sync(&server_accept_conn);
	}
	pr_info("simple web server LKM removed\n");
}

module_init(simple_webserver_lkm_init);
module_exit(simple_webserver_lkm_exit);
