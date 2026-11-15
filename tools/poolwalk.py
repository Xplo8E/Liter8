"""poolwalk - name every object in the autorelease pool at a releaseUntil crash.

At the EXC_BAD_ACCESS in AutoreleasePoolPage::releaseUntil the pool's pages
still hold every entry of the cycle. Walking them and decoding each entry's
ObjC class name identifies the dead pointer's neighbours, which identifies
the code that produced it. Pure SBProcess memory reads: no expression JIT
(expr is unavailable on hardened targets), so it works on this debugserver.
"""
import lldb
import struct

ISA_MASK = 0x00007FFFFFFFFFF8


def _read(process, addr, size):
    err = lldb.SBError()
    data = process.ReadMemory(addr, size, err)
    if err.Fail() or data is None or len(data) < size:
        return None
    return data


def _qword(process, addr):
    d = _read(process, addr, 8)
    return None if d is None else struct.unpack('<Q', d)[0]


def _cstring(process, addr, cap=64):
    d = _read(process, addr, cap)
    if d is None:
        return None
    z = d.find(b'\x00')
    if z < 0:
        return None
    try:
        return d[:z].decode('utf-8', 'replace')
    except Exception:
        return None


def _class_name(process, obj_ptr):
    """Decode an object's class through the iOS 17+ encrypted isa.

    Verified live on 24B119: the stored isa word = (tag << 40) |
    class_addr | low flag bits; the low-40 candidate lands in a
    __objc_data section. The class -> name path on the device runs
    through a ptrauth-signed bits word this script cannot strip without
    the runtime, so the CLASS ADDRESS is returned instead and resolved
    against the IDA cache db (slide 0x8694000, one shared-cache slide
    for every module)."""
    raw_isa = _qword(process, obj_ptr)
    if raw_isa is None:
        return None
    cls = raw_isa & 0x000000FFFFFFFFFF & ~0x7
    if cls == 0:
        return None
    return "class@0x%x" % cls


def _describe_entry(process, entry_val, dead):
    p = entry_val & 0x0007FFFFFFFFFFFF  # strip pool signing bits
    if p == 0:
        return "nil"
    tag = ""
    if p == dead:
        tag = "  <<< THE DEAD OBJECT"
    name = _class_name(process, p)
    if name is None:
        # not a live object: dump the first word for the freelist pattern
        w = _qword(process, p)
        return "0x%x [dead/invalid, word0=0x%s]%s" % (
            p, ("%016x" % w) if w is not None else "????", tag)
    return "0x%x [%s]%s" % (p, name, tag)


def poolwalk(debugger, command, exe_ctx, result, _internal):
    target = exe_ctx.GetTarget()
    thread = exe_ctx.GetThread()
    if not thread.IsValid():
        result.AppendMessage("no thread")
        return
    frame = thread.GetFrameAtIndex(0)
    regs = {}
    for r in frame.GetRegisters():
        for m in r:
            regs[m.GetName()] = m.GetValue()
    def reg_u64(name):
        v = regs.get(name, '0x0')
        return int(v, 16) if isinstance(v, str) and v.startswith('0x') else int(v)
    x0 = reg_u64('x0')
    process = target.GetProcess()

    result.AppendMessage("dead object x0 = 0x%x" % x0)

    # The releaseUntil frame is #1: its x19 = stop token, x20 = next.
    f1 = thread.GetFrameAtIndex(1)
    token = None
    nxt = None
    for r in f1.GetRegisters():
        for m in r:
            if m.GetName() == 'x19':
                token = int(m.GetValue(), 16)
            elif m.GetName() == 'x20':
                nxt = int(m.GetValue(), 16)
    result.AppendMessage("releaseUntil token(x19)=0x%x next(x20)=0x%x" % (token or 0, nxt or 0))
    if not token or not nxt:
        result.AppendMessage("no token/next: cannot walk")
        return

    # Entries live between the page's stack start and next; the token page and
    # current page are usually the same for the update-cycle pool. Walk from
    # the lower of the two addresses up to next, one pointer per slot.
    lo, hi = min(token, nxt), max(token, nxt)
    if hi - lo > 0x400:
        result.AppendMessage("span too large (0x%x), clamping to 0x400" % (hi - lo))
        lo = hi - 0x400
    result.AppendMessage("walking slots 0x%x .. 0x%x" % (lo, hi))
    addr = lo & ~7
    n = 0
    classes = {}
    while addr < hi and n < 128:
        v = _qword(process, addr)
        if v is not None and v != 0:
            d = _describe_entry(process, v, x0)
            result.AppendMessage("slot 0x%x: 0x%x %s" % (addr, v, d))
            c = _qword(process, v & 0x0007FFFFFFFFFFFF)
            if c is not None:
                cls = c & 0x000000FFFFFFFFFF & ~0x7
                if cls:
                    classes[cls] = classes.get(cls, 0) + 1
            n += 1
        addr += 8
    result.AppendMessage("class candidates (device domain, resolve in IDA as addr-0x8694000):")
    for cls in sorted(classes):
        result.AppendMessage("  0x%x x%d -> ida 0x%x" % (cls, classes[cls], cls - 0x8694000))
    result.AppendMessage("done (%d non-empty entries)" % n)


def __lldb_init_module(debugger, _internal):
    debugger.HandleCommand(
        'command script add -f poolwalk.poolwalk poolwalk')
    print("poolwalk installed: run `poolwalk` at the releaseUntil freeze")
