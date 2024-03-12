"""
Module provides TACACS+ packet flag variables
Classes:
    None

Functions:
    None
"""

# Set for testing purposes only
TAC_PLUS_UNENCRYPTED_FLAG = 0x01

# Versioning
TAC_PLUS_MAJOR_VER = 0xc
TAC_PLUS_MINOR_VER = 0x0
TAC_PLUS_MINOR_VER_ONE = 0x1

# Packet types
TAC_PLUS_AUTHEN = 0x01
TAC_PLUS_AUTHOR = 0x02
TAC_PLUS_ACCT = 0x03
TAC_PLUS_PACKET_TYPES = {
    'TAC_PLUS_AUTHEN': TAC_PLUS_AUTHEN,
    'TAC_PLUS_AUTHOR': TAC_PLUS_AUTHOR,
    'TAC_PLUS_ACCT': TAC_PLUS_ACCT,
}

# Services
TAC_PLUS_AUTHEN_SVC_NONE = 0x00
TAC_PLUS_AUTHEN_SVC_LOGIN = 0x01
TAC_PLUS_AUTHEN_SVC = {
    'TAC_PLUS_AUTHEN_SVC_NONE': TAC_PLUS_AUTHEN_SVC_NONE,
    'TAC_PLUS_AUTHEN_SVC_LOGIN': TAC_PLUS_AUTHEN_SVC_LOGIN,
}

# Authentication types
TAC_PLUS_AUTHEN_LOGIN = 0x01
TAC_PLUS_AUTHEN_TYPE_NOT_SET = 0x00
TAC_PLUS_AUTHEN_TYPE_ASCII = 0x01
TAC_PLUS_AUTHEN_TYPE_PAP = 0x02
TAC_PLUS_AUTHEN_TYPE_CHAP = 0x03
TAC_PLUS_AUTHEN_TYPES = {
    'TAC_PLUS_AUTHEN_TYPE_NOT_SET': TAC_PLUS_AUTHEN_TYPE_NOT_SET,
    'TAC_PLUS_AUTHEN_TYPE_ASCII': TAC_PLUS_AUTHEN_TYPE_ASCII,
    'TAC_PLUS_AUTHEN_TYPE_PAP': TAC_PLUS_AUTHEN_TYPE_PAP,
    'TAC_PLUS_AUTHEN_TYPE_CHAP': TAC_PLUS_AUTHEN_TYPE_CHAP,
}

# Authentication methods
TAC_PLUS_AUTHEN_METH_NOT_SET = 0x00
TAC_PLUS_AUTHEN_METH_NONE = 0x01
TAC_PLUS_AUTHEN_METH_KRB5 = 0x02
TAC_PLUS_AUTHEN_METH_LINE = 0x03
TAC_PLUS_AUTHEN_METH_ENABLE = 0x04
TAC_PLUS_AUTHEN_METH_LOCAL = 0x05
TAC_PLUS_AUTHEN_METH_TACACSPLUS = 0x06
TAC_PLUS_AUTHEN_METH_GUEST = 0x08
TAC_PLUS_AUTHEN_METH_RADIUS = 0x10
TAC_PLUS_AUTHEN_METH_KRB4 = 0x11
TAC_PLUS_AUTHEN_METH_RCMD = 0x20
TAC_PLUS_AUTHEN_METHODS = {
    'TAC_PLUS_AUTHEN_METH_NOT_SET': TAC_PLUS_AUTHEN_METH_NOT_SET,
    'TAC_PLUS_AUTHEN_METH_NONE': TAC_PLUS_AUTHEN_METH_NONE,
    'TAC_PLUS_AUTHEN_METH_KRB5': TAC_PLUS_AUTHEN_METH_KRB5,
    'TAC_PLUS_AUTHEN_METH_LINE': TAC_PLUS_AUTHEN_METH_LINE,
    'TAC_PLUS_AUTHEN_METH_ENABLE': TAC_PLUS_AUTHEN_METH_ENABLE,
    'TAC_PLUS_AUTHEN_METH_LOCAL': TAC_PLUS_AUTHEN_METH_LOCAL,
    'TAC_PLUS_AUTHEN_METH_TACACSPLUS': TAC_PLUS_AUTHEN_METH_TACACSPLUS,
    'TAC_PLUS_AUTHEN_METH_GUEST': TAC_PLUS_AUTHEN_METH_GUEST,
    'TAC_PLUS_AUTHEN_METH_RADIUS': TAC_PLUS_AUTHEN_METH_RADIUS,
    'TAC_PLUS_AUTHEN_METH_KRB4': TAC_PLUS_AUTHEN_METH_KRB4,
    'TAC_PLUS_AUTHEN_METH_RCMD': TAC_PLUS_AUTHEN_METH_RCMD,
}

# Authentication actions
TAC_PLUS_AUTHEN_LOGIN = 0x01
TAC_PLUS_AUTHEN_CHPASS = 0x02
TAC_PLUS_AUTHEN_SENDAUTH = 0x04
TAC_PLUS_AUTHEN_ACTIONS = {
    'TAC_PLUS_AUTHEN_LOGIN': TAC_PLUS_AUTHEN_LOGIN,
    'TAC_PLUS_AUTHEN_CHPASS': TAC_PLUS_AUTHEN_CHPASS,
    'TAC_PLUS_AUTHEN_SENDAUTH': TAC_PLUS_AUTHEN_SENDAUTH,
}

# Authentication flags
TAC_PLUS_CONTINUE_FLAG_ABORT = 0x01

# Authentication statuses
TAC_PLUS_AUTHEN_STATUS_PASS = 0x01
TAC_PLUS_AUTHEN_STATUS_FAIL = 0x02
TAC_PLUS_AUTHEN_STATUS_GETDATA = 0x03
TAC_PLUS_AUTHEN_STATUS_GETUSER = 0x04
TAC_PLUS_AUTHEN_STATUS_GETPASS = 0x05
TAC_PLUS_AUTHEN_STATUS_RESTART = 0x06
TAC_PLUS_AUTHEN_STATUS_ERROR = 0x07
TAC_PLUS_AUTHEN_STATUS_FOLLOW = 0x21
TAC_PLUS_AUTHEN_STATUS = {
    'TAC_PLUS_AUTHEN_STATUS_PASS': TAC_PLUS_AUTHEN_STATUS_PASS,
    'TAC_PLUS_AUTHEN_STATUS_FAIL': TAC_PLUS_AUTHEN_STATUS_FAIL,
    'TAC_PLUS_AUTHEN_STATUS_GETDATA': TAC_PLUS_AUTHEN_STATUS_GETDATA,
    'TAC_PLUS_AUTHEN_STATUS_GETUSER': TAC_PLUS_AUTHEN_STATUS_GETUSER,
    'TAC_PLUS_AUTHEN_STATUS_GETPASS': TAC_PLUS_AUTHEN_STATUS_GETPASS,
    'TAC_PLUS_AUTHEN_STATUS_RESTART': TAC_PLUS_AUTHEN_STATUS_RESTART,
    'TAC_PLUS_AUTHEN_STATUS_ERROR': TAC_PLUS_AUTHEN_STATUS_ERROR,
    'TAC_PLUS_AUTHEN_STATUS_FOLLOW': TAC_PLUS_AUTHEN_STATUS_FOLLOW,
}

TAC_PLUS_REPLY_FLAG_NOTSET = 0x00
TAC_PLUS_REPLY_FLAG_NOECHO = 0x01
TAC_PLUS_REPLY_FLAGS = {
    'TAC_PLUS_REPLY_FLAG_NOTSET': TAC_PLUS_REPLY_FLAG_NOTSET,
    'TAC_PLUS_REPLY_FLAG_NOECHO': TAC_PLUS_REPLY_FLAG_NOECHO,
}

# Priveleges
TAC_PLUS_PRIV_LVL_MIN = 0x00
TAC_PLUS_PRIV_LVL_USER = 0x01
TAC_PLUS_PRIV_LVL_MAX = 0x0F
TAC_PLUS_PRIV_LVL = {
    'TAC_PLUS_PRIV_LVL_MIN': TAC_PLUS_PRIV_LVL_MIN,
    'TAC_PLUS_PRIV_LVL_USER': TAC_PLUS_PRIV_LVL_USER,
    'TAC_PLUS_PRIV_LVL_MAX': TAC_PLUS_PRIV_LVL_MAX,
}

# Authorization statuses
TAC_PLUS_AUTHOR_STATUS_PASS_ADD = 0x01
TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02
TAC_PLUS_AUTHOR_STATUS_FAIL = 0x10
TAC_PLUS_AUTHOR_STATUS_ERROR = 0x11
TAC_PLUS_AUTHOR_STATUS_FOLLOW = 0x21
TAC_PLUS_AUTHOR_STATUS = {
    'TAC_PLUS_AUTHOR_STATUS_PASS_ADD': TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
    'TAC_PLUS_AUTHOR_STATUS_PASS_REPL': TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
    'TAC_PLUS_AUTHOR_STATUS_FAIL': TAC_PLUS_AUTHOR_STATUS_FAIL,
    'TAC_PLUS_AUTHOR_STATUS_ERROR': TAC_PLUS_AUTHOR_STATUS_ERROR,
    'TAC_PLUS_AUTHOR_STATUS_FOLLOW': TAC_PLUS_AUTHOR_STATUS_FOLLOW,
}

# Accounting methods
TAC_PLUS_ACCT_FLAG_START = 0x02
TAC_PLUS_ACCT_FLAG_STOP = 0x04
TAC_PLUS_ACCT_FLAG_WATCHDOG = 0x08
TAC_PLUS_ACCT_FLAGS = {
    'TAC_PLUS_ACCT_FLAG_START' : TAC_PLUS_ACCT_FLAG_START,
    'TAC_PLUS_ACCT_FLAG_STOP' : TAC_PLUS_ACCT_FLAG_STOP,
    'TAC_PLUS_ACCT_FLAG_WATCHDOG' : TAC_PLUS_ACCT_FLAG_WATCHDOG,
}

# Accounting statuses
TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01
TAC_PLUS_ACCT_STATUS_ERROR = 0x02
TAC_PLUS_ACCT_STATUS_FOLLOW = 0x21
