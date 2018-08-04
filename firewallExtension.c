#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include <linux/namei.h>
#include <linux/version.h>

MODULE_AUTHOR ("Eike Ritter <E.Ritter@cs.bham.ac.uk>");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL");

struct list *li;


static DECLARE_RWSEM(rwsem);
#define PROC_ENTRY_FILENAME "firewallExtension"

/***********************************************************************************
	Linked List
***********************************************************************************/
typedef struct node{
  int port;
  char* file;
  struct node* next;
} node;

typedef struct list{
  node * head;
  node * tail;
} list;


void init(list * l) {
li = (list *) kmalloc(sizeof(struct list)+1,GFP_KERNEL);
	if (li == NULL) {
		printk(KERN_ALERT "Failed to initialise module\n");
		return;
	}
	memset(li,0,sizeof(struct list)+1);
  li->head = NULL;
  li->tail = NULL;
}

int push(list * l, int port, char* file){
	struct node* newNode;
	//Make new Node
	newNode = (node*)kmalloc(sizeof(struct node)+1,GFP_KERNEL);
	if(newNode == NULL){
		return -1;
	}
	memset(newNode,0,sizeof(struct node)+1);
	newNode->port = port;
	newNode->file = file;
	newNode->next = NULL;
	//mutex_lock (&devLock);
	// list empty
	if (l->head == NULL) {
		l->head = newNode;
		l->tail = newNode;
	} //List Not empty 
	else {
		l->tail->next = newNode;
		l->tail = newNode;
	}
	//mutex_unlock (&devLock);
	return 0;
}

void destroy(list *l){
  node* next = l->head;
  node* toFree;
  if (l == NULL)
	  return;
  while (next != NULL) {
    toFree = next;
    next = next->next;
    kfree(toFree);
  }
  kfree(l);
  l = NULL;
  return;
}

void print_list(list * l){
  node* currentNode;
  if(l->head == NULL){
    return;
  }
 
  currentNode = l->head;
  while(currentNode != NULL){
     currentNode = currentNode->next;
  }
}

int hasPort(list * l, int port) {
	node* currentNode = l->head;
	while (currentNode != NULL) {
		if (currentNode->port == port)
			return 1;
		currentNode = currentNode->next;
	}
	return 0;
}

int contains(list * l, int port, char* path) {
	node* currentNode = l->head;
	while (currentNode != NULL) {
		if (strcmp(currentNode->file, path) == 0) {
			if (currentNode->port == port)
				return 1;
			}
		currentNode = currentNode->next;
	}
	return 0;
}











/********************************************************
	File Operations For Communicating With Userspace
********************************************************/
ssize_t kernelWrite (struct file *file, const char __user *buffer, size_t count, loff_t *offset) {
	long num;
	char* filePath;
	char* port;
	char* line;
	char* p;
	line = kmalloc(count+2,GFP_KERNEL);
	if(line == NULL){
		return -1;
	}
	memset(line,0,count+2);
	if (copy_from_user(line, buffer, count))
		return -EFAULT;
	if (strcmp(line,"-c")==0) {
		down_write (&rwsem);
		destroy(li);
		init(li);
		up_write (&rwsem);
		return 0;
	}
	p = strchr(line, ' ');
	filePath = kmalloc(strlen(p+1)+1,GFP_KERNEL);
	if (filePath == NULL)
		return -EFAULT;
	memset(filePath, 0, strlen(p+1)+1);
	strcpy(filePath,p+1);
	if(filePath[strlen(filePath)-1]=='\n')
        filePath[strlen(filePath)-1]='\0';
	port = kmalloc(p-line+1,GFP_KERNEL);
	if (port == NULL)
		return -EFAULT;
	memset(port,0,p-line+1);
	strncpy(port,line,p-line);
	port[strlen(port)] = '\0';
	kstrtol(port,10,&num);
	down_write (&rwsem);
	push(li,(int) num,filePath);
	up_write (&rwsem);
	kfree(line);
	kfree(port);
	return 0;
}
  
ssize_t kernelRead(struct file *filp,	/* see include/linux/fs.h   */
			   char *buffer,	/* buffer to fill with data */
			   size_t length,	/* length of the buffer     */
			   loff_t * offset) {
	down_read (&rwsem);
	print_list(li);
	up_read (&rwsem);
	return 0;
}

/* 
 * The file is opened - we don't really care about
 * that, but it does mean we need to increment the
 * module's reference count. 
 */
int procfs_open(struct inode *inode, struct file *file)
{
    try_module_get(THIS_MODULE);
	return 0;
}

/* 
 * The file is closed - again, interesting only because
 * of the reference count. 
 */
int procfs_close(struct inode *inode, struct file *file)
{
    printk (KERN_INFO "kernelWrite closed\n");
    module_put(THIS_MODULE);
    return 0;		/* success */
}

const struct file_operations File_Ops_4_Our_Proc_File = {
    .owner = THIS_MODULE,
    .write 	 = kernelWrite,
	.read  = kernelRead,
    .open 	 = procfs_open,
    .release = procfs_close,
};





/********************************************************
	Firewall
********************************************************/


int getPath(char** holder) {
	struct path path;
    pid_t mod_pid;
    struct dentry *procDentry;
	char* buffer;
    char cmdlineFile[80];
    int res;
	char* temp;
    
	buffer = kmalloc(1024,GFP_KERNEL);
	if (buffer == NULL)
		return -EFAULT;
	memset(buffer,0,1024);
    printk (KERN_INFO "findExecutable module loading\n");
    /* current is pre-defined pointer to task structure of currently running task */
    mod_pid = current->pid;
    snprintf (cmdlineFile, 80, "/proc/%d/exe", mod_pid); 
    res = kern_path (cmdlineFile, LOOKUP_FOLLOW, &path);
    if (res) {
		printk (KERN_INFO "Could not get dentry for %s!\n", cmdlineFile);
		return -EFAULT;
    }
	procDentry = path.dentry;
	temp = dentry_path_raw(procDentry, buffer, 1024);
	*holder = kmalloc(strlen(temp)+1,GFP_KERNEL);
	if (*holder == NULL)
		return -EFAULT;
	memset(*holder,0,strlen(temp)+1);
    
	strncpy(*holder,temp,strlen(temp));
	kfree(buffer);
    return 0;
}





int isAllowed(int port, char* proc) {
	if (hasPort(li,port) == 0)
		return 1;
	if (contains(li,port,proc) == 1)
		return 1;
	return 0;
}







static struct proc_dir_entry *Our_Proc_File;

/* make IP4-addresses readable */

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]


struct nf_hook_ops *reg;

// the firewall hook - called for each outgoing packet 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0)
#error "Kernel version < 4.4 not supported!"
//kernels < 4.4 need another firewallhook!
#endif
unsigned int FirewallExtensionHook (void *priv,
				    struct sk_buff *skb,
				    const struct nf_hook_state *state) {

    struct tcphdr *tcp;
    struct tcphdr _tcph;
    struct sock *sk;
    struct mm_struct *mm;
	char* path;


  sk = skb->sk;
  if (!sk) {
    printk (KERN_INFO "firewall: netfilter called with empty socket!\n");;
    return NF_ACCEPT;
  }

  if (sk->sk_protocol != IPPROTO_TCP) {
    printk (KERN_INFO "firewall: netfilter called with non-TCP-packet.\n");
    return NF_ACCEPT;
  }

    /* get the tcp-header for the packet */
    tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
    if (!tcp) {
	printk (KERN_INFO "Could not get tcp-header!\n");
	return NF_ACCEPT;
    }
    if (tcp->syn) {
	struct iphdr *ip;
	
	printk (KERN_INFO "firewall: Starting connection \n");
	ip = ip_hdr (skb);
	if (!ip) {
	    printk (KERN_INFO "firewall: Cannot get IP header!\n!");
	}
	else {
	    printk (KERN_INFO "firewall: Destination address = %u.%u.%u.%u\n", NIPQUAD(ip->daddr));
	}
	printk (KERN_INFO "firewall: destination port = %d\n", ntohs(tcp->dest)); 
		
	

	if (in_irq() || in_softirq() || !(mm = get_task_mm(current))) {
		printk (KERN_INFO "Not in user context - retry packet\n");
		return NF_ACCEPT;
	}
	mmput(mm);

	
	getPath(&path);
	

	if (isAllowed(ntohs (tcp->dest),path) == 0) {
	    tcp_done (sk); /* terminate connection immediately */
	    printk (KERN_INFO "Connection shut down\n");
	    return NF_DROP;
	}
    }
    return NF_ACCEPT;	
}

static struct nf_hook_ops firewallExtension_ops = {
	.hook    = FirewallExtensionHook,
	.pf      = PF_INET,
	.priority = NF_IP_PRI_FIRST,
	.hooknum = NF_INET_LOCAL_OUT
};


int init_module(void) {

  int errno;

  errno = nf_register_hook (&firewallExtension_ops); /* register the hook */
  if (errno) {
    printk (KERN_INFO "Firewall extension could not be registered!\n");
  } 
  else {
    printk(KERN_INFO "Firewall extensions module loaded\n");
  }

  Our_Proc_File = proc_create_data (PROC_ENTRY_FILENAME, 0644, NULL, &File_Ops_4_Our_Proc_File, NULL);
    
  /* check if the /proc file was created successfuly */
  if (Our_Proc_File == NULL){
	printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
       PROC_ENTRY_FILENAME);
	return -ENOMEM;
  }
    
    printk(KERN_INFO "/proc/%s created\n", PROC_ENTRY_FILENAME);
	
	
	init(li);


  
  
  // A non 0 return means init_module failed; module can't be loaded.
  return errno;
  
}


void cleanup_module(void) {
    remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
	nf_unregister_hook (&firewallExtension_ops); 
	printk(KERN_INFO "/proc/%s removed\n", PROC_ENTRY_FILENAME);  
	printk(KERN_INFO "kernelWrite:Proc module unloaded.\n");
	destroy(li);
    printk(KERN_INFO "Firewall extensions module unloaded\n");
}  
