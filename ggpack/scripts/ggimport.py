import r2pipe
import json
import sys
import os.path

def import_ggfile (input_path):
    r = r2pipe.open("#!pipe")

    files = r.cmdj('fj')[1:-1]
    sym_name = 'sym.%s' % os.path.basename(input_path)

    for f in files:
        if f['name'] == sym_name:
            print 'importing %s into %s...' % (input_path, sym_name)
            size = os.path.getsize(input_path)
            if size != f['size']:
                diff = size - f['size']
                sign = '+'
                if diff < 0:
                    sign = '-'
                r.cmd('r%s%d@%d' % (sign, diff, f['offset']))
                r.cmd('wf %s@%d' % (input_path, f['offset']))
            return

    print 'cannot find %s in ggpack' % sym_name

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'please provide the input file path'
    else:
        input_path = os.path.abspath(sys.argv[1])
        import_ggfile(input_path)






