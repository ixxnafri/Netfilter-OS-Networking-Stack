#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/inet.h>

//struct holding set of hook funtion options
static struct nf_hook_ops nfho1;
static struct nf_hook_ops nfho2;

//initalize the condition to drop packet
static unsigned char *drop_if = "lo";
static unsigned int drop_ip = 0x272eeb67;

//function to be called by hook NF_INET_PRE_ROUTING
unsigned int hook_func_incoming(void *priv, struct sk_buff *skb, const struct nf_hook_state * state){
    struct iphdr *ip = ip_hdr(skb);
    struct tcphdr *tcp = tcp_hdr(skb);
    unsigned int port = tcp->dest;

    //when port is 8888 or interface is lo, drop the packet
    if(strcmp(state->in->name, "lo")){
        return NF_DROP;
    }

    else if(port == 8888)
    {
        printk("Dropped packet from port %x\n", port);
        return NF_DROP;
    }
    else{
        char *s = state->in->name;
        printk("packet accept\n");
        return NF_ACCEPT;
    }
}

//function to be called by hook NF_INET_POST_ROUTING
unsigned int hook_func_outgoing(void *priv, struct sk_buff *skb, const struct nf_hook_state * state){
    struct iphdr *ip = ip_hdr(skb);


    //when ip is 103.235.46.39, drop the packet
    if(ip->daddr == drop_ip){
        printk("Dropped packet towards %x\n", ip->daddr);
        return NF_DROP;
    }
    else{
        printk("Allowed packet towards %x\n", ip->daddr);     
        return NF_ACCEPT;
    }
}

//Called when module loaded using 'insmod'
int init_module(){
    //function to call when conditions below met
    nfho1.hook = hook_func_incoming;
    nfho2.hook = hook_func_outgoing;

    //hook in Netfilter
    nfho1.hooknum = NF_INET_PRE_ROUTING;
    nfho2.hooknum = NF_INET_POST_ROUTING;

    //IPV4 packets
    nfho1.pf = PF_INET;
    nfho2.pf = PF_INET;

    //set priority for hook functions
    nfho1.priority = NF_IP_PRI_FIRST;
    nfho2.priority = NF_IP_PRI_CONNTRACK;

    //register hook
    nf_register_hook(&nfho1);
    nf_register_hook(&nfho2);

    printk(KERN_INFO "custom firewall loaded\n");
    return 0;
}
void cleanup_module()
{ 
  printk("custom firewall unloaded\n");
  nf_unregister_hook(&nfho1);                //cleanup and unregister hook
}
