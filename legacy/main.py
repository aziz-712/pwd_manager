# password manager: generator and handler
# Developed by ABBASSI Ahmed Aziz

from file_handler import create_file, search, add_to_file, read_file, update, delete, remove_file


# choose the running mode
def get_mode():
    modes = ['1', '2', '3', '4', '5', '6', '7', 'q', 'Q', 'quit']
    mode = '0'
    while mode not in modes:
        mode = input(f'What mode you want? ({", ".join(modes)}): ')
        if mode not in modes:
            print("Please choose a valid mode!")
    return mode


def console_log():
    modes = [
        'Create a new file',
        'Add to file',
        'Read file',
        'Search in file',
        'Update file',
        'Delete domain from file',
        'Delete file',
        'Enter (q or Q or quit) to quit!'
    ]

    # this piece of code is for formatting output in console
    lens = []  # the length of each mode
    for mode in modes:
        lens.append(((len(modes[5]) - len(mode)) // 2) * ' ')

    space = ((len(modes[-1]) - len("Password Handler")) // 2) * "*"
    print(f'{space}Password Handler{space}')

    for _ in range(len(modes) - 1):
        print(f'{_ + 1}. {lens[_]}{modes[_]}{lens[_]}')

    print(modes[-1])


# the main program of our software
def main():
    console_log()
    mode = '0'
    while mode not in ['q', 'Q', 'quit']:
        mode = get_mode()
        match mode:
            case '1':
                create_file()
            case '2':
                add_to_file()
            case '3':
                read_file()
            case '4':
                search()
            case '5':
                update()
            case '6':
                delete()
            case '7':
                remove_file()
            case 'q' | 'Q' | 'quit':
                print('Program closed successfully!')


if __name__ == '__main__':
    main()
