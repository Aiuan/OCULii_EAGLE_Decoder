def log(text):
    print(text)

def log_BLUE(text):
    print('\033[0;34;40m{}\033[0m'.format(text))

def log_YELLOW(text):
    print('\033[0;33;40m{}\033[0m'.format(text))

def log_GREEN(text):
    print('\033[0;32;40m{}\033[0m'.format(text))

def log_RED(text):
    print('\033[0;31;40m{}\033[0m'.format(text))