netfilter-iptc
==============
> notes about netfilter and iptc library

> [ref: netfilter hacking how to](https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO.txt)

> [ref: iptc linux documentation](http://tldp.org/HOWTO/Querying-libiptc-HOWTO/)

> [ref: networking kernel flow linux fondation](https://wiki.linuxfoundation.org/networking/kernel_flow)

> [ref: iptables digital ocean documentation](https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture)

> [ref: kernel module makefiles](https://www.kernel.org/doc/Documentation/kbuild/makefiles.txt)


kernel space
------------
#### basic makefile
```sh
ccflags-y += -std=gnu11
obj-m += my_mod.o

default:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

#### module initialization
```c
#include <linux/kernel.h>
#include <linux/module.h>

//! Module entry point method
static int __init m_init(void)
{
    printk(KERN_DEBUG "Start basic module\n");
    return 0;
}

//! Module exit point method
static void __exit m_clean(void)
{
    printk(KERN_DEBUG "Stop basic module\n");
}

module_init(m_init);
module_exit(m_clean);
```

#### netfilter types
```c
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>

//! Alias type for hook options
typedef struct nf_hook_ops  t_hook_options;
//! Alias type for ip header
typedef struct iphdr        t_ip_header;
//! Alias type for udp header
typedef struct udphdr       t_udp_header;
//! Alias type for socket_buffer
typedef struct sk_buff      t_obj_buffer;
```

#### netfilter primitives
```c
//! Function to initialize hook options.
//! \param hook_options The netfilter hook options structure.
static void init_hook_options(t_hook_options * hook_options)
{
    hook_options->hook     = hook_callback;
    hook_options->hooknum  = NF_INET_LOCAL_IN;
    hook_options->pf       = PF_INET;
    hook_options->priority = NF_IP_PRI_FIRST;
}

...

//! Netfilter hook options
static t_hook_options hook_options;

//! Module init
init_hook_options(&hook_options);
nf_register_hook(&hook_options);

...

//! Module clean
nf_unregister_hook(&hook_options);
```

#### socket buffer manipulation
```c
t_ip_header  * ip_header  = ip_hdr(skb);
t_udp_header * udp_header = udp_hdr(obj_buffer);
```


user space
----------
#### iptc composition
```c
//! example from an iptables command:
//! iptables -A INPUT -p udp -dport 12345 -j DROP
//! which means:
//!
//! 1 entry/rule in table 'filter' chain 'input'
//! |
//! |---- 1 match
//! |     |
//! |     |---- 1 udp match with destination port
//! |
//! |---- 1  target
//!       |
//!       |---- 0 target option
//! 
//! 1 iptc entry may store multi matches and target options
//!
//! Warning:
//! - addresses are stored in network byte order
//! - ports are stored in host byte order
```

#### iptc types
```c
#include <netinet/in.h>                 // address structures
#include <linux/netfilter.h>            // netfilter structures
#include <libiptc/libiptc.h>            // iptc chain manipulation

typedef struct iptc_handle      t_handle;
typedef struct ipt_entry        t_entry;
typedef struct ipt_entry_match  t_match;
typedef struct ipt_udp          t_match_udp;
typedef struct ipt_entry_target t_target;

static const size_t s_entry        = XT_ALIGN(sizeof(t_entry));
static const size_t s_match        = XT_ALIGN(sizeof(t_match));
static const size_t s_match_udp    = XT_ALIGN(sizeof(t_match_udp));
static const size_t s_target       = XT_ALIGN(sizeof(t_target));
```

#### iptc primitives
```c
//! handle and entry must be checked
t_handle * handle = iptc_init("filter");
t_entry  * entry  = ...

...

// Note: 'dmesg' may provide more information about failures
int status = 0;
status = iptc_append_entry("INPUT", entry, handle);
if (!status)
{
    printf("append entry error: %s\n", iptc_strerror(errno));
}
status = iptc_commit(handle);
if (!status)
{
    printf("commit handle error: %s\n", iptc_strerror(errno));
}
iptc_free(handle);

// free entry
```

#### structure manipulation
```c
//! Note: required memory should be allocated first to the ipc entry and init with 0
t_entry * entry = calloc(1, entry_size);

...

entry->target_offset = s_entry + s_match + s_match_udp;
entry->next_offset   = entry_size;
entry->ip.proto      = IPPROTO_UDP;

...

t_match * match = (t_match *) entry->elems;
match->u.match_size = s_match + s_match_udp;

...

t_target * target = (t_target *) (entry->elems + s_match + s_match_udp);
target->u.target_size = s_target + s_target_queue;
```
