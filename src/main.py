#!/usr/bin/python3

from bcc import BPF
import argparse
import sys
import json

# arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i', action='store', dest='inputf', help="Input Fname", default="")
parser.add_argument('-o', action='store', dest='ouputf', help="Ouput Fname", default="")
parser.add_argument('-d',                 dest='debugs', help="Print Debug", action='store_true')
parser.add_argument('-f', action='store', dest='filter', help="Filter Comm", default="")

# Define BPF stubs
hdr_txt = """
#include <linux/sched.h>

BPF_PERF_OUTPUT(events);
#define MAX_SIZE 255
struct data_t {
    u32 pid;
    u32 cpuid;
    u64 ts;

    char comm[TASK_COMM_LEN];
    char buff[MAX_SIZE + 1];
};

"""
rty_txt = "int\t"
arg_txt = "(struct pt_regs *ctx) {\n static char * str ="

bpf_txt = """;\n
    struct data_t data = {};
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    data.cpuid = bpf_get_smp_processor_id();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    __builtin_memcpy(&data.buff, str, strlen(str));
    data.buff[MAX_SIZE] = 0;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""

def append_u_txt(fname, sym, probe_type, txt):
  fn_name = sym + "_" + probe_type
  probe_name = probe_type + ":" + fname + ":" + sym
  txt = append_bpf_txt(fn_name, probe_name, txt)
  return txt, fn_name

def append_uretprobe_txt(probes, txt):
  closures = []
  for fname in probes.keys():
    for sym in probes[fname]:
      txt, fn_name = append_u_txt(fname, sym, "uretprobe", txt)
      func = lambda bpf_ctx, fname=fname, sym=sym, fn_name=fn_name  : bpf_ctx.attach_uretprobe(name=fname, sym=sym, fn_name=fn_name)
      closures.append(func)
  return txt, closures

def append_uprobe_txt(probes, txt):
  closures = []
  for fname in probes.keys():
    for sym in probes[fname]:
      txt, fn_name = append_u_txt(fname, sym, "uprobe", txt)
      func = lambda bpf_ctx, fname=fname, sym=sym, fn_name=fn_name : bpf_ctx.attach_uprobe(name=fname, sym=sym, fn_name=fn_name)
      closures.append(func)
  return txt, closures

def append_kretprobe_txt(probes, txt):
  closures = []
  for sym in probes:
    txt, fn_name = append_u_txt("kernel", sym, "kretprobe", txt)
    func = lambda bpf_ctx, sym=sym, fn_name=fn_name  : bpf_ctx.attach_kretprobe(event=sym, fn_name=fn_name)
    closures.append(func)
  return txt, closures

def append_kprobe_txt(probes, txt):
  closures = []
  for sym in probes:
    txt, fn_name = append_u_txt("kernel", sym, "kprobe", txt)
    func = lambda bpf_ctx, sym=sym, fn_name=fn_name  : bpf_ctx.attach_kprobe(event=sym, fn_name=fn_name)
    closures.append(func)
  return txt, closures

allowed_probe_types = {"uprobe"     : append_uprobe_txt,
                       "kprobe"     : append_kprobe_txt,
                       "uretprobe"  : append_uretprobe_txt,
                       "kretprobe"  : append_kretprobe_txt}

def create_bpf_ctx(input_dict, debug, txt=hdr_txt):
  closures = []
  for probe_type in input_dict.keys():
    if not probe_type in allowed_probe_types.keys():
      raise Exception("Probe type " + probe_type + " not supported")
    txt, close_list = allowed_probe_types[probe_type](input_dict[probe_type], txt)
    closures.extend(close_list)
  bpf_ctx = BPF(text=txt)
  if debug:
    print(txt)
  for closure in closures:
    closure(bpf_ctx)
  return bpf_ctx

def append_bpf_txt(fn_name, probe_name, txt):
  return txt + rty_txt + fn_name + arg_txt + '"' + probe_name + '"' + bpf_txt

filters = None
def print_event(cpu, data, size):
  output = bpf_ctx["events"].event(data)
  if filters is None or filters == output.comm:
    print("%s:%s\t%ld\t%ld\t%ld" % (output.buff, output.comm, output.pid, output.cpuid, output.ts))

if __name__ == "__main__":
  args = parser.parse_args();
  inputf = sys.stdin
  if args.inputf != "" or args.inputf is None:
    inputf = open(args.inputf)
  if args.ouputf != "" or args.ouputf is None:
    sys.stdout = open(args.ouputf, "w")
  if args.filter != "":
    filters = bytes(args.filter, 'ascii')
  input_dict = json.load(inputf)
  bpf_ctx = create_bpf_ctx(input_dict, args.debugs)
  # Print header
  print("P_NM\tP_ID\tC_ID\tNS")

  # Open perf "events" buffer, loop with callback to handle_event
  bpf_ctx["events"].open_perf_buffer(print_event)

  # Format output
  while 1:
    try:
      bpf_ctx.perf_buffer_poll()
    except KeyboardInterrupt:
      print()
      exit()
