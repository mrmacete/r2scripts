import r2pipe
import tempfile
import os
import shutil
import errno

class TestCase:
    def __init__ (self, comment):
        self.tmp_dir = tempfile.mkdtemp(prefix='ggpack_test_')
        self.comment = comment
        self.reason = 'GOOD LUCK'

    def make_dir (self, dir_path):
        path = os.path.join(self.tmp_dir, dir_path)
        try:
            os.makedirs(path)
        except OSError as exc:
            if exc.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise

        return path

    def _cleanup (self):
        if self.tmp_dir != None:
            shutil.rmtree(self.tmp_dir)

    def setup (self):
        print '%s: Setup' % self.comment

    def test (self):
        print '%s: Running' % self.comment

    def teardown (self):
        print '%s: Teardown' % self.comment
        self._cleanup()


class TestResize(TestCase):
    def __init__ (self, comment, resize_at, delta):
        TestCase.__init__(self, comment)
        self.delta = delta
        self.resize_at = resize_at

    def setup (self):
        TestCase.setup(self)
        self.dump_before = self.make_dir('dump_before')
        self.dump_after = self.make_dir('dump_after')
        self.r2.cmd('$ggexport=#!pipe python ./ggexport.py')

    def test (self):
        TestCase.test(self)
        self.dump_files(self.dump_before)
        self.flags_before = self.r2.cmdj('fj')
        # self.index_before = self.r2.cmdj('=!pij')
        f = self.flags_before
        file_names = [f[i]['name'] for i in xrange(1,len(f)-1) if f[i]['size'] > 0 and (self.resize_at < f[i]['offset'] or self.resize_at > (f[i]['offset'] + f[i]['size']))]

        self.r2.cmd('s %d' % self.resize_at);
        sign = '+'
        if self.delta < 0:
            sign = ''
        self.r2.cmd('r%s%d' % (sign, self.delta))

        self.flags_after = self.r2.cmdj('fj')
        # self.index_after = self.r2.cmdj('=!pij')

        self.dump_files(self.dump_after)

        if not self.check_flags():
            return False

        if not self.check_files_equal(file_names):
            return False

        """if not self.check_index():
            print 'Error in check_index'
            return False"""
        return True


    def dump_files (self, dest_dir):
        self.r2.cmd('$ggexport %s' % dest_dir)

    def check_files_equal (self, file_names):
        norm_names = [name[4:] for name in file_names]
        pairs = [(os.path.join(self.dump_before, name), os.path.join(self.dump_after, name)) for name in norm_names]
        for before, after in pairs:
            if not self.is_file_equal(before, after):
                return False
        return True

    def check_flags (self):
        length = len(self.flags_before)
        if length != len(self.flags_after):
            self.reason = 'flags: number of flags should remain the same'
            return False

        for i in xrange(length):
            fb = self.flags_before[i]
            fa = self.flags_after[i]
            if i == 0 and fb['size'] != fa['size'] != 8:
                self.reason = 'flags: header wrong size'
                return False
            elif i == (length - 1) and fb['name'] != fa['name'] != "index_directory":
                self.reason = 'flags: index_directory not found or out of place'
                return False
            else:
                if self.resize_at >= fb['offset'] + fb['size']:
                    if fa['offset'] != fb['offset']:
                        self.reason = 'flags: offset of %s should not be moved' % fa['name']
                        return False
                    if fa['size'] != fb['size']:
                        self.reason = 'flags: size of %s should not change' % fa['name']
                        return False
                elif self.resize_at < fb['offset']:
                    if fa['offset'] != fb['offset'] + self.delta:
                        self.reason = 'flags: offset of %s should be moved' % fa['name']
                        return False
                    if fa['size'] != fb['size']:
                        self.reason = 'flags: size of %s should not change' % fa['name']
                        return False
                else:
                    if fa['offset'] != fb['offset']:
                        self.reason = 'flags: offset of %s should not be moved' % fa['name']
                        return False
                    if fa['size'] != fb['size'] + self.delta:
                        self.reason = 'flags: size of %s should be %u' % (fa['name'], fb['size'] + self.delta)
                        return False
        return True

    def check_index (self):
        return False

    def is_file_equal (self, before, after):
        with open(before, 'rb') as fb, open(after, 'rb') as fa:
            b = fb.read()
            a = fa.read()
            if len(a) != len(b):
                self.reason = '%s wrong size (%d != %d)' % (os.path.basename(after), a, b)
                return False
            length = len(a)
            for i in xrange(length):
                x = b[i]
                y = a[i]
                if x != y:
                    self.reason = '%s wrong content at 0x%x (%x -> %x)' % (os.path.basename(after), i, ord(x), ord(y))
                    return False
            return True

        self.reason = 'error opening something i guess'
        return False


def run_suite (file_name, suite):
    results = []
    for test in suite:
        tmp_dir = tempfile.mkdtemp('ggpack_test_')
        base = os.path.basename(file_name)
        tmp_file_name = os.path.join(tmp_dir, base)
        shutil.copyfile(os.path.abspath(file_name), tmp_file_name)
        print 'opening: %s' % tmp_file_name
        r2 = r2pipe.open('ggpack://%s' % tmp_file_name, ['-w'])
        test.r2 = r2
        try:
            test.setup()
            if test.test():
                results.append("TEST %s/%s: SUCCESS!" % (base, test.comment))
            else:
                results.append("TEST %s/%s: FAIL! (%s)" % (base, test.comment, test.reason))
        finally:
            test.teardown()
        r2.quit()
        shutil.rmtree(tmp_dir)
    return results

def run_tests ():
    suite1 = []
    suite1.append(TestResize("resize up small", 0x049f40e3, 8))
    suite1.append(TestResize("resize up big", 0x049f40e3, 40001))
    suite1.append(TestResize("resize down small", 0x049f40bd, -3))
    suite1.append(TestResize("resize down big", 0x19a5df7b, -40001))

    suite2 = []
    suite2.append(TestResize("resize up", 0x1ac6f346, 100))
    suite2.append(TestResize("resize down", 0x1581f734, -40001))

    results = []

    results += run_suite('../test/twp.ggpack1', suite1)
    results += run_suite('../test/twp.ggpack2', suite2)

    print '\n'.join(results)

if __name__ == '__main__':
    run_tests()



