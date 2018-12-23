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

//function to be called by hook NF_INET_PRE_ROUTING
unsigned int hook_func_incoming(void *priv, struct sk_buff *skb, const struct nf_hook_state * state){
    struct iphdr *ip; 
    struct tcphdr *tcp;

    if(skb){
        iph = = ip_hdr(skb);

    }

if (skb) {
        iph = ip_hdr(skb);

        if (iph && iph->protocol && (iph->protocol == IPPROTO_TCP)) {
            tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);

            if (tcph->source) {
                if ((tcph->urg && tcph->fin && tcph->psh) && (!tcph->ack && !tcph->syn && !tcph->rst)) {
                    printk(KERN_DEBUG "Running TCP Xmas Scan!\n");
                } else if (!tcph->urg && !tcph->fin && !tcph->psh && !tcph->ack && !tcph->syn && !tcph->rst) {
                    printk(KERN_DEBUG "Running TCP NULL Scan!\n");
                } else if ((tcph->fin) && (!tcph->urg &&!tcph->ack && !tcph->syn && !tcph->rst && !tcph->psh)) {
                    printk(KERN_DEBUG "Running TCP FIN Scan!\n");
                } else if ((tcph->syn) && (!tcph->fin && !tcph->psh && !tcph->urg && !tcph->ack && !tcph->rst)) {
                    printk(KERN_DEBUG "Running TCP SYN Scan!\n");
                }
            }
        }
    }

return NF_ACCEPT;
}


//Called when module loaded using 'insmod'
int init_module(){
    //function to call when conditions below met
    nfho1.hook = hook_func_incoming;

    //hook in Netfilter
    nfho1.hooknum = NF_INET_PRE_ROUTING;

    //IPV4 packets
    nfho1.pf = PF_INET;

    //set priority for hook functions
    nfho1.priority = NF_IP_PRI_FIRST;

    //register hook
    nf_register_hook(&nfho1);

    printk(KERN_INFO "custom firewall loaded\n");
    return 0;
}
void cleanup_module()
{ 
  nf_unregister_hook(&nfho1);                //cleanup and unregister hook
  printk("custom proj removed\n");
}

