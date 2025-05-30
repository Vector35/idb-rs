#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum command {
    OP1,
    OP2,
    OP3,
    OP4,
};

struct args {
    int value;
    char sub_value;
    enum command cmd;
};

void print_arg(struct args *args) {
    if (args->value != 0) {
        printf("value: %d", args->value);
    }
    printf("sub_value %d", args->sub_value);
    switch (args->cmd) {
        case OP1:
            printf("OP1");
            break;
        case OP2:
            printf("OP2");
            break;
        case OP3:
            printf("OP3");
            break;
        case OP4:
            printf("OP4");
            break;
        default:
            printf("INVALID");
            exit(1);
    }
}

struct args parse_arg(int argc, char *argv[]) {
    if (argc != 3 && argc != 4) {
        printf("Need 2 or 3 args");
        exit(1);
    }
    struct args args;
    int counter = 1;
    if (argc == 4) {
        sscanf(argv[counter++], "%d", &args.value);
    } else {
        args.value = 0;
    }
    char *sub_value = argv[counter++];
    if (strlen(sub_value) != 1) {
        printf("arg sub_value need to be size 1");
        exit(1);
    }
    args.sub_value = argv[counter++][0];

    char *cmd_raw = argv[counter++];
    long cmd = 0;
    sscanf(cmd_raw, "%ld", &cmd);
    switch (cmd) {
        case 0:
            args.cmd = OP1;
            break;
        case 1:
            args.cmd = OP2;
            break;
        case 2:
            args.cmd = OP3;
            break;
        case 3:
            args.cmd = OP4;
            break;
        default:
            printf("Invalid cmd");
            exit(1);
    }

    return args;
}

int main(int argc, char *argv[])
{
    struct args args = parse_arg(argc, argv);
    print_arg(&args);
    return 0;
}
