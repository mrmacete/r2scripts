import r2pipe
import json
import sys

def dumpall (outdir):
    r = r2pipe.open("#!pipe")

    files = r.cmdj('fj')[1:-1]

    for f in files:
        out_name = '%s/%s' % (outdir, f['name'][4:])
        print 'dumping %s...' % out_name
        r.cmd('wtf %s %d@%d' % (out_name, f['size'], f['offset']))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'please provide the output dir'
    else:
        outdir = sys.argv[1]
        dumpall(outdir)






