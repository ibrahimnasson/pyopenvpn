

def parse_block_tag(block, line_n, line):
    key = line[1:-1]
    if key[0] == '/':
        if block is None:
            raise ValueError("Block end while not in block (line %d)" %
                             (line_n))
        if key[1:] != block:
            raise ValueError("Block end %r, expected %r (line %d)" %
                             (key[1:], block, line_n))
        block = None
    else:
        if block is not None:
            raise ValueError("Block start while in block (line %d)" %
                             (line_n))
        block = key
        if key not in Settings.BLOCK_TAGS:
            raise ValueError("Invalid block key %r (line %d)" %
                             (key, line_n))
    return block


class Settings(dict):
    BLOCK_TAGS = ('ca', 'cert', 'key', 'tls-auth')

    def parse_option(self, option):
        key, args, *_ = option.split(' ', 1) + [True]
        self[key] = args

    @classmethod
    def from_text(cls, text):
        o = cls()

        block = None
        for line_n, line in enumerate(text.split("\n")):
            line = line.split('#', 1)[0]
            line = line.strip()

            if not line:
                continue

            if line[0] == '<' and line[-1] == '>':
                block = parse_block_tag(block, line_n, line)
            elif block is not None:
                o[block] += line + "\n"
            else:
                o.parse_option(line)

        return o

    @classmethod
    def from_options(cls, options):
        options = options.split(',')
        options = (o.strip() for o in options)
        options = [o for o in options if o]

        if len(options) < 2:
            raise ValueError("Options string too short")
        if options.pop(0) != 'V4':
            raise ValueError("Options string doesnt start with V4")

        obj = cls()
        for opt in options:
            obj.parse_option(opt)
        return obj

    @classmethod
    def from_push(cls, options):
        options = options.split(',')
        options = (o.strip() for o in options)
        options = [o for o in options if o]

        if len(options) < 2:
            raise ValueError("Options string too short")
        if options.pop(0) != 'PUSH_REPLY':
            raise ValueError("Options string doesnt start with PUSH_REPLY")

        obj = cls()
        for opt in options:
            obj.parse_option(opt)
        return obj

    @classmethod
    def from_file(cls, path):
        with open(path) as f:
            return cls.from_text(f.read())

    def get_options(self):
        """ Returns an OpenVPN options strings
        That's a few important settings that are exported and compared,
        one one line, separated by ",".
        """
        # FIXME some more options must be checked, documented on
        # options_string in options.c
        keys = ('dev-type', 'link-mtu', 'tun-mtu', 'proto', 'comp-lzo',
                'cipher', 'auth', 'keysize', 'key-method', 'tls-client')
        return 'V1,' + ','.join(k + ('' if self[k] is True else (' ' + str(self[k])))
                                for k in keys if self[k] is not False)


DEFAULT_SETTINGS = {
    'tls-client': True,
    'cipher': 'BF-CBC',
    'auth': 'SHA1',
    'dev-type': 'tun',
    'link-mtu': '1542',
    'tun-mtu': '1500',
    'proto': 'UDPv4',
    'comp-lzo': True,
    'keysize': '128',
    'key-method': '2',
}

