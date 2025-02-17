# mem_watcher

## mem_watcher介绍

memwatcher是一款基于eBPF的内存监测工具，其设计的目的就是为了可以让用户能够在主机环境上可以快捷的检测到Linux内存的详细信息。
通过高效的数据收集和精准的监控能力，帮助用户可以有效的监控主机内存情况。
使用了eBPF（Extended Berkeley Packet Filter）来监控内核中的几个关键事件，主要涉及到内存管理方面的几个功能：
第一：`get_page_from_freelist：`

- 监控页面分配过程中的某些关键参数。
- 捕获了页面分配时的一些重要信息，比如所用的gfp_mask、order、alloc_flags等。

第二：`shrink_page_list：`

- 监控页面收缩（shrink）过程中的一些参数。
- 捕获了页面收缩时的关键参数，如nr_to_reclaim、nr_reclaimed等。

第三：`finish_task_switch：`

- 监控进程切换完成时的内存相关参数。
- 捕获了进程切换时的一些内存使用情况，如pid、vsize、rss等。

第四：`get_page_from_freelist：`

- 监控页面分配的另一方面，可能是为了提供更全面的内存分配情况。
- 捕获了更多与页面分配相关的内存统计信息，如anon_inactive、file_inactive等。

通过收集这些信息，可以用于监控系统内存的使用情况、诊断内存相关的性能问题以及进行性能优化。

第五：

内存泄露是指程序在申请内存后，无法释放或未能及时释放，从而导致系统内存的不断消耗，最终导致程序的崩溃或性能的下降。这种现象一般发生在程序中有大量的动态内存分配和释放操作，如果程序员忘记或者疏忽了释放内存，就有可能导致内存泄露。

eBPF 提供了一种高效的机制来监控和追踪系统级别的事件，包括内存的分配和释放。通过 eBPF，可以跟踪内存分配和释放的请求，并收集每次分配的调用堆栈。然后，分析这些信息，找出执行了内存分配但未执行释放操作的调用堆栈，这有助于程序员找出导致内存泄漏的源头。

------
## 背景意义

内存子系统是Linux内核中是一个相对复杂的模块，内核中几乎所有的数据、缓存、程序指令都有内存模块参与管理。在内存不足的情况下，这些数据就会被存储在磁盘的交换空间中，但是磁盘的处理速度相对与内存非常慢，当内存和磁盘频繁进行数据交换时，缓慢的磁盘读写速度非常影响系统性能。系统可能因内存不足从而终止那些占用内存较大的进程，导致程序运行故障。因此准确的监控分析内存性能状况就变得非常重要。

目前，传统的内存性能分析工具通过读取proc文件系统下的数据，经过简单的处理后呈现给用户，方便管理人员随时了解系统状况。然而这些工具的灵活性非常差，单个工具输出的信息有限。系统维护人员在分析性能问题时常常需要借助多个工具才能进行。步骤繁琐且工具本身对系统性能也有一定影响。随着ebpf技术在系统可观测上的发展，利于ebpf非侵入式的数据获取方式已被大多数企业、高校认可并取得了一定的研究成果。ebpf的可编程性可以让管理人员灵活的获取系统的运行数据，而且在数据的提取粒度上有着传统工具无法比拟的优势。现在，ebpf作为Linux内核顶级子系统，已经成为实现Linux内核可观测性、网络和内核安全的理想技术。

------

# mem_watcher据体代码的分析。

## procstat

### 采集信息：

| 参数     | 含义                     |
| -------- | ------------------------ |
| vsize    | 进程使用的虚拟内存       |
| size     | 进程使用的最大物理内存   |
| rssanon  | 进程使用的匿名页面       |
| rssfile  | 进程使用的文件映射页面   |
| rssshmem | 进程使用的共享内存页面   |
| vswap    | 进程使用的交换分区大小   |
| vdata    | 进程使用的私有数据段大小 |
| vpte     | 进程页表大小             |
| vstk     | 进程用户栈大小           |
### 功能

主要是用于跟踪用户空间进程的内存使用情况。具体功能是在用户空间进程切换时，记录切换前进程的内存信息，并将这些信息写入环形缓冲区中。

### 分析

`BPF_KPROBE`标记了一个内核探针函数，挂载在`finish_task_switch`结束时，这个函数用于捕获进程切换事件。
内核探针函数首先通过`bpf_get_current_pid_tgid()`获取当前进程的PID，然后通过prev参数获取切换前的进程结构体指针。
然后判断当前进程的PID是否是要跟踪的用户进程的PID，如果是则直接返回，不做任何处理。
接着获取切换前进程的PID，并判断是否是要跟踪的用户进程的PID，如果是则直接返回。
如果不是要跟踪的进程，则从`last_val`哈希表中查找上一次记录的内存状态。
如果没有找到，则更新`last_val`哈希表，将该进程的PID作为键，将值设置为1。
如果找到了上一次的记录，并且上一次的值与当前值相同，则说明内存状态没有变化，直接返回。
如果上一次的记录与当前值不同，则说明内存状态发生了变化，需要记录内存信息。
通过`bpf_ringbuf_reserve()`函数在环形缓冲区中分配空间，并填充内存事件信息。
最后通过`bpf_ringbuf_submit()`函数将填充好的内存事件信息提交到环形缓冲区中。
### 载点及挂载原因

挂载点：finish_task_switch

挂载原因：

首先，获取进程级别内存使用信息首先需要获取到进程的task_struct结构体，其中在mm_struct成员中存在一个保存进程当前内存使用状态的数组结构，因此有关进程的大部分内存使用信息都可以通过这个数组获得。其次，需要注意函数的插入点，插入点的选取关系到数据准确性是否得到保证，而在进程的内存申请，释放，规整等代码路径上都存在页面状态改变，但是数量信息还没有更新的相关结构中的情况，如果插入点这两者中间，数据就会和实际情况存在差异，所有在确保可以获取到进程PCB的前提下，选择在进程调度代码路径上考虑。而finish_task_switch函数是新一个进程第一个执行的函数，做的事却是给上一个被调度出去的进程做收尾工作，所有这个函数的参数是上一个进程的PCB，从这块获得上一个进程的内存信息就可以确保在它没有再次被调度上CPU执行的这段时间内的内存数据稳定性。因此最后选择将程序挂载到finish_task_switch函数上。以下是调度程序处理过程：

![](./image/6.png)

数据来源有两部分，一个是mm_struc结构本身存在的状态信息，另一个是在mm_rss_stat结构中，它总共统计四部分信息，内核定义如下：

![](./image/7.png)

## sysstat

### 采集信息：

| 参数           | 含义                             |
| -------------- | -------------------------------- |
| active         | LRU活跃内存大小                  |
| inactive       | LRU不活跃内存大小                |
| anon_active    | 活跃匿名内存大小                 |
| anon_inactive  | 不活跃匿名内存大小               |
| file_active    | 活跃文件映射内存大小             |
| file_inactive  | 不活跃文件映射内存大小           |
| unevictable    | 不可回收内存大小                 |
| dirty          | 脏页大小                         |
| writeback      | 正在回写的内存大小               |
| anonpages      | RMAP页面                         |
| mapped         | 所有映射到用户地址空间的内存大小 |
| shmem          | 共享内存                         |
| kreclaimable   | 内核可回收内存                   |
| slab           | 用于slab的内存大小               |
| sreclaimable   | 可回收slab内存                   |
| sunreclaim     | 不可回收slab内存                 |
| NFS_unstable   | NFS中还没写到磁盘中的内存        |
| writebacktmp   | 回写所使用的临时缓存大小         |
| anonhugepages  | 透明巨页大小                     |
| shmemhugepages | shmem或tmpfs使用的透明巨页       |
###  功能

提取各种类型内存的活动和非活动页面数量，以及其他内存回收相关的统计数据，除了常规的事件信息外，程序还输出了与内存管理相关的详细信息，包括了不同类型内存的活动（active）和非活动（inactive）页面，未被驱逐（unevictable）页面，脏（dirty）页面，写回（writeback）页面，映射（mapped）页面，以及各种类型的内存回收相关统计数据。

### 分析

分别用last_val1、last_val2、last_val3 三个哈希表记录上次统计的值，这里的键是不同类型页面的数量。
`BPF_KPROBE(get_page_from_freelist_second, ...)` 是一个 Kprobe 函数，用于跟踪从空闲页列表获取页面的情况。
在函数内部，首先获取当前进程的 PID，并与 `user_pid` 进行比较，如果相同则直接返回。
通过 `BPF_CORE_READ` 读取内存分配相关的统计信息，包括匿名页面的活动状态和非活动状态下的数量、文件页面的活动状态和非活动状态下的数量、不可驱逐页面的数量等。
通过三个哈希表 last_val1、last_val2、last_val3 查找上次统计的值，如果不存在则将新的统计值更新到哈希表中，如果存在且与当前值相同，则表示重复统计，直接返回。
在环形缓冲区中预留空间，用于记录系统统计事件，并将获取的内存分配相关的统计信息填充到事件结构体中。
最后，提交系统统计事件到环形缓冲区中。
这个代码的挂载函数和paf代码相同在这里不再进行二次分析。
### 挂载点及挂载原因

挂载点：get_page_from_freelist

原因：

首先，内存状态数据的提取需要获取到内存节点pglist_data数据结构，这个结构是对内存的总体抽象。pglist_data数据结构末尾有个vm_stat的数组，里面包含了当前内存节点所有的状态信息。所有只需要获取到pglist_data结构就能拿到当前的内存状态信息。但是物理内存分配在选择内存节点是通过mempolicy结构获取，无法获得具体的节点结构。选择内存节点的函数处理流程如下：

```c
struct mempolicy *get_task_policy(struct task_struct *p)
{
        struct mempolicy *pol = p->mempolicy;//根据当前task_struct取得
        int node;

        if (pol)
                return pol; 

        node = numa_node_id();
        if (node != NUMA_NO_NODE) {//存在其他节点
                pol = &preferred_node_policy[node];
                /* preferred_node_policy is not initialised early in boot */
                if (pol->mode)
                        return pol; 
        }    

        return &default_policy;//不存在其他节点返回本地节点
}
```

经过对内存申请的内部结构alloc_context分析(这是内存申请过程中临时保存相关参数的结构)，当前内存节点是可以通过：alloc_context——>zoneref——>zone——>pglist_data的路径访问到。

其次，因为函数执行申请内存的过程对获取内存节点数据的影响不大，所以只要可以获得alloc_context数据结构，在整个申请路径上挂载函数都是可以的。sysstat工具选择的挂载点是get_page_from_freelist函数。这个函数是快速物理内存分配的入口函数。因为内核在进行物理内存分配时，都会进入快速路径分配，只有当失败时才会进入慢速路径，所以get_page_from_freelist函数是必经函数。整个处理过程以及函数关系如下：

![](./image/1.png)

但是，经过对proc文件系统的打印函数meminfo_proc_show函数的分析得知，影响内存性能的参数在vm_stat中无法全部获得。一部分数据需要遍历当前内存节点包含的所有内存管理区zone结构中vm_stat数组获得，一部分需要读取全局变量vm_node_stat获得。但是内核的全局变量不会作为函数参数参与数据处理，目前还没具体方法获得这部分数据。

### 存在问题

■ 部分性能数据存在于内核全局变量中，而这些数据不会作为函数参数存储在栈中，因此这些数据目前还没实现统计

■ 因为内核对内存管理不会是物理内存的全部容量，而且最大管理内存的数据结构是内存结点，所以以上统计数据是以当前内存结点实际管理的内存容量为基准。

■ 当前剩余内存总量的统计需要遍历所有内存管理区来统计，但是由于内存管理区的空闲页面信息存储在数组第一个位置，使用指针指向时，统计到的数据不准确，使用变量统计会出现数据类型错误的报告。

## paf

### 采集信息

| 参数    | 含义                                 |
| ------- | ------------------------------------ |
| min     | 内存管理区处于最低警戒水位的页面数量 |
| low     | 内存管理区处于低水位的页面数量       |
| high    | 内存管理区处于高水位的页面数量       |
| present | 内存管理区实际管理的页面数量         |
| flag    | 申请页面时的权限（标志）             |
### 功能

主要是监控内核中的`get_page_from_freelist`函数。这个函数在内核中用于从内存空闲页列表中获取一个页面。
程序主要是输出present(当前内存中可用的页面数量)，min(在这个阈值下，系统可能会触发内存压缩)，low(在这个阈值下，系统进行内存回收)，high(在这个阈值上，认为内存资源充足)，flag(用于内存分配的状态)。

### 分析

该程序挂载在内核函数`get_page_from_freelist`的前面。
首先，获取当前进程的PID，并检查是否等于`user_pid`，如果相等，则直接返回，表示不监控当前进程。
然后，通过`bpf_map_lookup_elem()`查找last_val哈希表中是否已经存在当前`gfp_mask`的值，如果不存在，则将当前`gfp_mask`的值插入哈希表中。
如果已经存在，并且与上一次观察到的值相同，则直接返回，表示不需要重复记录相同的`gfp_mask`值。
接着，通过`bpf_ringbuf_reserve()`尝试在环形缓冲区中预留一段空间，用于存储事件数据。如果预留失败，则直接返回。
之后，通过`BPF_CORE_READ()`读取给定的内核数据结构`alloc_context`中的一些字段的值，并将这些值存储在定义好的事件结构体e中。
最后，通过`bpf_ringbuf_submit()`将填充好的事件结构体提交到环形缓冲区中。

内存申请失败一般集中在申请权限不够或者是权限冲突导致，申请权限不够是当内核申请优先级较低的页面时，虽然内存管理区有足够的页面满足这次申请数量，但是当前剩余空闲页面少于最低警戒水位，因此导致内核无法成功分配页面的情况。权限冲突，例如内核在开启CMA机制下导致的页面页面申请失败的情况，这种情况下管理区空闲页面需要减去CMA机制占用内存才是当前可分配内存。相关权限判断代码如下：

添加CMA权限代码路径mm/page_alloc.c

```c
static inline unsigned int
gfp_to_alloc_flags(gfp_t gfp_mask)
{
	unsigned int alloc_flags = ALLOC_WMARK_MIN | ALLOC_CPUSET;
    ...
	alloc_flags |= (__force int) (gfp_mask & __GFP_HIGH);
    ...
	if (gfp_mask & __GFP_KSWAPD_RECLAIM)
			alloc_flags |= ALLOC_KSWAPD;
    
#ifdef CONFIG_CMA
	if (gfpflags_to_migratetype(gfp_mask) == MIGRATE_MOVABLE)
			alloc_flags |= ALLOC_CMA;
#endif
	return alloc_flags;
}
```

CMA机制内存处理代码:

```c
bool __zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
                         int classzone_idx, unsigned int alloc_flags, long free_pages)
{
   ...
#ifdef CONFIG_CMA
        if (!(alloc_flags & ALLOC_CMA))
                free_pages -= zone_page_state(z, NR_FREE_CMA_PAGES);
#endif  
  
        if (free_pages <= min + z->lowmem_reserve[classzone_idx])
                return false;
	...
#ifdef CONFIG_CMA
       if ((alloc_flags & ALLOC_CMA) &&
                !list_empty(&area->free_list[MIGRATE_CMA])) {
                        return true;
                }
#endif
}  
```
挂载点：get_page_from_freelist

原因:

经过对内核源码的分析，页面申请失败分析工具的理想挂载点应该是慢速路径的入口函数（__alloc_pages_slowpath）。但是这个函数不允许ebpf程序挂载，而且这个函数内部也不存在合理的挂载点，所有将函数挂载点选在快速路径的入口函数get_page_from_freelist上。因为页面申请的控制结构体ac在这两个函数之间不存在信息更改，所以可以确保这两个函数传递的ac结构体是相同的，不会对提取出来的数据产生影响。为了确保数据确实是在页面申请失败的情况下才会打印数据，需要对alloc_pages_nodemask函数的返回值进行挂载，当alloc_pages_nodemask函数没有返回页面结构体page时，也就是页面申请失败的情况下单元提取的数据。

### 存在问题

■ 打印出来的内存申请标志与申请内存传递进去的标志不符，分析原因可能内核在进行alloc_pages函数之前有对标志位进行处理。

■ 因为内存管理区的剩余内存空间处在vm_stat数组第一位，经过分析，使用指针提取的数组第一个数据总是存在差异，需要调整。

■ 对打印的标志位需要进一步解析，方便快速确认当前申请页面类型。


## pr

### 采集信息

| 参数          | 含义                                         |
| ------------- | -------------------------------------------- |
| reclaim       | 要回收的页面数量                             |
| reclaimed     | 已经回收的页面数量                           |
| unqueue_dirty | 还没开始回写和还没在队列等待的脏页           |
| congested     | 正在块设备上回写的页面，含写入交换空间的页面 |
| writeback     | 正在回写的页面                               |
### 功能

主要用于监控内核中的`shrink_page_list`函数。
整个BPF程序的功能是监控`shrink_page_list`函数的调用，当函数被调用时，记录特定的内核数据（包括`nr_reclaimed`等值），并将这些数据存储在环形缓冲区中，以供用户空间程序使用。
跟踪内核中页面的回收行为，记录回收的各个阶段，例如要回收的页面，以回收的页面，等待回收的脏页数，要写回的页数(包括交换空间中的页数)以及当前正在写回的页数。

### 分析

在这个函数内部，首先通过`bpf_get_current_pid_tgid()`获取当前进程的PID，并与`user_pid`比较，如果相等，则直接返回，表示不监控当前进程。
通过`BPF_CORE_READ()`读取给定的内核数据结构`scan_control`中的一些字段的值，并将这些值存储在定义好的事件结构体中。
通过`bpf_ringbuf_reserve()`尝试在环形缓冲区中预留一段空间，用于存储事件数据。如果预留失败，则直接返回。
通过bpf_ringbuf_submit()将填充好的事件结构体提交到环形缓冲区中。
### 挂载点与挂载原因

挂载点

shrink_page_list

挂载原因

shrink_page_list函数是页面回收后期指向函数，主要操作是遍历链表中每一个页面，根据页面的属性确定将页面添加到回收队列、活跃链表还是不活跃链表.这块遍历的链表是在上一级函数 shrink_inactive_list中定义的临时链表，因为一次最多扫描32个页面，所有链表最多含有32个页面。在shrink_page_list这个函数中还有一个重要操作是统计不同状态的页面数量并保存在scan_control结构体中。而工具数据提取的位置就是找到这个结构体并获取有关性能指标。因为这个提取的数据都是内核函数实时更改的，所有具有较高准确性。

scan_control结构体是每次进行内存回收时都会被回收进程重新定义，所有会看到数据是一个增长状态，之后有回归0，这和挂载点也有一定关系。
## memleak

### 功能

代码主要用于跟踪内核内存分配和释放的情况，并记录相关的统计信息。

### 分析

首先定义了几个 BPF 映射：
`sizes`：用于存储与每个进程 ID（PID）关联的内存分配大小。
`allocs`：用于存储与内存分配相关信息，以分配的返回地址为索引。
`combined_allocs`：另一个哈希映射，用于根据堆栈跟踪 ID 聚合内存分配信息。
`stack_traces`：堆栈跟踪映射，用于将堆栈跟踪转换为堆栈跟踪 ID。

定义了两个 `uprobes`（用户空间探测点）：
`malloc_enter`：此探测点附加到 `malloc` 函数的入口点。它将当前进程 ID（pid）的内存分配大小记录到 `sizes` 映射中。
`malloc_exit`：此探测点附加到 `malloc` 函数的退出点。它从 `sizes` 映射中检索先前记录的大小，将其与分配的返回地址关联，并使用此信息更新 `allocs` 映射。此外，它根据堆栈跟踪更新 `combined_allocs` 映射以聚合分配信息。

定义了一个 `uretprobe`（用户空间返回探测点）：
`malloc_exit`：此探测点附加到 `malloc` 函数的退出点。它从 sizes 映射中检索先前记录的大小，将其与分配的返回地址关联，并使用此信息更新 `allocs` 映射。此外，它根据堆栈跟踪更新 `combined_allocs` 映射以聚合分配信息。

定义了一个 `uprobe`（用户空间探测点）：
`free_ente`r：此探测点附加到 `free` 函数的入口点。它从 allocs 映射中检索与正在释放的地址相关的分配信息。然后，它更新 `combined_allocs` 映射以反映释放。

# 工具的使用方法说明

## 功能介绍

mem_watcher工具可以通过一系列的命令控制参数来控制其具体的检测行为：我们可以通过sudo ./mem_watcher -h来查看工具支持的功能

```
 select function:
  -a, --paf                  print paf (内存页面状态报告)
  -p, --pr                   print pr (页面回收状态报告)
  -r, --procstat             print procstat (进程内存状态报告)
  -s, --sysstat              print sysstat (系统内存状态报告)
  -l, --memleak=PID          print memleak (内存泄漏检测)
```

- -a 输出的信息包括时间戳、进程ID、虚拟内存大小、物理内存等。输出的内容根据用户的选择（特定PID、是否显示RSS等）而变化。除了常规的事件信息外，程序还输出了与内存管理相关的详细信息，主要是present(当前内存中可用的页面数量)，min(在这个阈值下，系统可能会触发内存压缩)，low(在这个阈值下，系统进行内存回收)，high(在这个阈值上，认为内存资源充足)，flag(用于内存分配的状态)。
- -p 跟踪内核中页面的回收行为，记录回收的各个阶段，例如要回收的页面，以回收的页面，等待回收的脏页数，要写回的页数(包括交换空间中的页数)以及当前正在写回的页数。
- -r 主要是用于跟踪用户空间进程的内存使用情况。具体功能是在用户空间进程切换时，记录切换前进程的内存信息。
- -s 提取各种类型内存的活动和非活动页面数量，以及其他内存回收相关的统计数据，除了常规的事件信息外，程序还输出了与内存管理相关的详细信息，包括了不同类型内存的活动（active）和非活动（inactive）页面，未被驱逐（unevictable）页面，脏（dirty）页面，写回（writeback）页面，映射（mapped）页面，以及各种类型的内存回收相关统计数据。
- -l 输出了用户态造成内存泄漏的位置，包括内存泄漏指令地址对应符号名、文件名、行号，程序中尚未被释放的内存总量，未被释放的分配次数。

## 使用方法和结果展示

## paf

```c
sudo ./mem_watcher -a
MIN      LOW       HIGH     PRESENT  FLAG    
262144   5100      6120     262144   1100dca 
262144   5100      6120     262144   2800    
262144   5100      6120     262144   cc0     
262144   5100      6120     262144   d00     
262144   5100      6120     262144   2dc2     
......
```

## pr

```c
sudo ./mem_watcher -p
RECLAIM  RECLAIMED UNQUEUE  CONGESTED WRITEBACK
16893    0         0        0        0       
16893    24        0        0        0       
16893    24        0        0        0       
16893    40        0        0        0       
16893    64        0        0        0       
16893    64        0        0        0       
16893    66        0        0        0       
......   
```

## procstat

```c
sudo ./mem_watcher -r
......
01:08:50 334      0        0        0        0       
01:08:50 2984     13194    10242    2952     0       
01:08:50 0        0        0        0        0       
01:08:50 334      0        0        0        0       
01:08:50 5427     0        0        0        0       
01:08:50 0        0        0        0        0       
01:08:50 5427     0        0        0        0       
01:08:50 0        0        0        0        0       
01:08:50 0        0        0        0        0       
01:08:50 5427     0        0        0        0       
01:08:50 0        0        0        0        0       
01:08:50 5427     0        0        0        0       
01:08:50 2984     13194    10242    2952     0       
01:08:50 0        0        0        0        0       
01:08:50 5427     0        0        0        0       
01:08:50 334      0        0        0        0       
01:08:50 5427     0        0        0        0       
01:08:50 0        0        0        0        0       
01:08:50 0        0        0        0        0       
01:08:50 5427     0        0        0        0       
01:08:50 0        0        0        0        0    
......   
```

## sysstat

```c
sudo ./mem_watcher -s
......
ACTIVE   INACTVE  ANON_ACT ANON_INA FILE_ACT FILE_INA UNEVICT  DIRTY    WRITEBK  ANONPAG  MAP      SHMEM   
327644   2747936  1988     2278752  325656   469184   0        216      0        563728   249116   7832    
327652   2747616  1996     2278432  325656   469184   0        240      0        563844   249164   7832    
327652   2747616  1996     2278432  325656   469184   0        240      0        563864   249164   7832    
327652   2747844  1996     2278656  325656   469188   0        252      0        563864   249164   7832    
327652   2747844  1996     2278656  325656   469188   0        252      0        563884   249164   7832
......
```

## memleak

```
sudo ./mem_watcher -l 2429
......
stack_id=0x3c14 with outstanding allocations: total_size=4 nr_allocs=1
000055e032027205: alloc_v3 @ 0x11e9+0x1c /test_leak.c:11
000055e032027228: alloc_v2 @ 0x120f+0x19 /test_leak.c:17
000055e03202724b: alloc_v1 @ 0x1232+0x19 /test_leak.c:23
000055e032027287: memory_leak @ 0x1255+0x32 /test_leak.c:35
00007f1ca1d66609: start_thread @ 0x8530+0xd9
stack_id=0x3c14 with outstanding allocations: total_size=8 nr_allocs=2
000055e032027205: alloc_v3 @ 0x11e9+0x1c /test_leak.c:11
000055e032027228: alloc_v2 @ 0x120f+0x19 /test_leak.c:17
000055e03202724b: alloc_v1 @ 0x1232+0x19 /test_leak.c:23
000055e032027287: memory_leak @ 0x1255+0x32 /test_leak.c:35
00007f1ca1d66609: start_thread @ 0x8530+0xd9
......
```

------
## 测试环境

deepin20.6，Linux-5.17；

libbpf：[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)

