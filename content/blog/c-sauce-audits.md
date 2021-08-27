---
title: "C Sauce Audits"
categories: ["Hacking", "Source Code Auditing", "Binary Exploitation"]
tags: ["reversing", "hacking", "pentesting", "source audits", "Exploit Development", "static analysis"]
date: "2021-08-26"
type: "post"
weight: 400
keywords: "hacking static analysis c source code auditing"
---


> Everything is open source if you can afford a [binaryninja](https://binary.ninja/) licence


Very basic an incomplete overview of `C` focused source code auditing.

## Heap Vulnerabilities

### Use After Free (UAF)

+ Look at the order in which functions are called or can be called and trace the execution
+ Is memory free'd and then reused later?
+ If so it may be possible for an attacker to edit a freed chunk if they can control data which reaches the part of the code which reuses the freed pointer
+ Being able to edit a freed chunk forms the basis for most heap exploits

```c
char* ptr = (char*)malloc (SIZE);
...
if (err) {
    abrt = 1;
    free(ptr);
}
...
if (abrt) {
    logError("operation aborted before commit", ptr);
    }
```
```c
#include <stdio.h>
#include <unistd.h>

#define BUFSIZER1   512
#define BUFSIZER2   ((BUFSIZER1/2) - 8)

int main(int argc, char **argv) {
    char *buf1R1;
    char *buf2R1;
    char *buf2R2;
    char *buf3R2;

    buf1R1 = (char *) malloc(BUFSIZER1);
    buf2R1 = (char *) malloc(BUFSIZER1);

    free(buf2R1);

    buf2R2 = (char *) malloc(BUFSIZER2);
    buf3R2 = (char *) malloc(BUFSIZER2);

    strncpy(buf2R1, argv[1], BUFSIZER1-1);
    free(buf1R1);
    free(buf2R2);
    free(buf3R2);
}
```
#### Consequences

**Integrity**: The use of previously freed memory may corrupt valid data, if the memory area in question has been allocated and used properly elsewhere.

**Availability**: If chunk consolidation occurs after the use of previously freed data, the process may crash when invalid data is used as chunk information.

**Access Control (instruction processing)**: If malicious data is entered before chunk consolidation can take place, it may be possible to take advantage of a write-what-where primitive to execute arbitrary code.

### Heap Overflows

+ A heap overflow occurs when a write function does not consider or limit the size of the incoming data to be written to heap memory
+ If an attacker can controls this input they can overflow from the chunk written to into other chunks on the heap altering their data (meta data, contents) as they go 
+ A common scenario is `strcpy`ing more data then there is remaining space in the destination heap chunk
+ `strcat` is also a typical case 

**Protostar Level 1**

```c
undefined4 *chunk0;
void *ptr0;
undefined4 *chunk1;
void *ptr1;

chunk0 = (undefined4 *) malloc(8);
*chunk0 = 1;

ptr0 = malloc(8);
*(void **)(chunk0 + 1) = ptr0;

chunk1 = (undefined4 *)malloc(8);
*chunk1 = 2;

ptr1 = malloc(8);
*(void **)(chunk1 + 1) = ptr1;
strcpy((char *)chunk0[1],*(char **)(argv + 4));
strcpy((char *)chunk1[1],*(char **)(argv + 8));
```

### Double Free

+ The same heap chunk is freed twice potentially allowing an attacker to edit a freed chunk 
+ If an attacker can edit the freed chunks metadata they have a foothold for many heap exploits


```c
char *chunk = malloc(100);
free(chunk);
// ... 1000 lines
free(chunk);
```

### Custom malloc implementations

+ `__malloc_hook()`
    + Bad implementations


## Bad API Usage / Bad Practice

 *Use ~~your man~~ the man page and check description.* `man <function> 2`. The `C` language extensions for VSCode also give you a nice ability to hover over each funtion to get the correct paramters and a short description. Theres also the `whatis` command to get a quick summary of a unfamiliar function that you doubt is vulnerable. 

### `fmt`

+ Supplying user controlled data directly to format string functions leading to attacker arbitary read/write
+ Look out for vulnerable function calls like the following:

```c
/*
Database of vulnerable usage of 
format functions

    + printf        [X]
    + fprintf       [X]
    + sprintf       [X]
    + snprintf      [X]
    + vsnprintf     [X]
    + vsprintf      [X]
    + vfprintf      [X]
    + vprintf       [X]

    + dprintf       [X]
    + syslog        [X]

    + vscanf        [X]
    + vsscanf       [X]
    + fscanf        [X]
    + scanf         [X]
*/


/* take in argv[1] directly */
int 
main(int argc, char const *argv[])
{   
    // suppress compiler warning
    char *tmp = "empty";
    
    /* printf family */
    printf(argv[1]);
    fprintf(stdout, argv[1]);
    sprintf(tmp, argv[1]);
    snprintf(tmp, 0x100, argv[1]);
    vsnprintf(tmp, 0x100, argv[1], NULL);
    vsprintf(tmp, argv[1], NULL);
    vfprintf(stdout, argv[1], NULL);
    vprintf(argv[1], NULL);
    
    /* logging */
    dprintf(LOG_ERR, argv[1]);
    syslog(LOG_INFO, argv[1]);
    
    /* scan */
    vscanf(argv[1], NULL);
    vsscanf(tmp, argv[1], NULL);
    fscanf(stdin, argv[1]);
    scanf(argv[1]);
    return 0;
}

```


### `memset`

+ incorrect usage
    + `memset(s, 100, 0)` <-- fills 0 bytes of memory with at s with 100
+ correct usage
    + `memset(s, 0, 100)` <-- fills 100 bytes of memory at s with 0's

### `gets`
+ `gets()` - just keeps reading into buffer
    + Always bad
      
### `fgets`

+ `fgets(char *s, int size, FILE *input)` 
    + Reads one byte less than size and appends newline 
    + **Dangerous** when `buffer < size + 1` 

### `read`

+ `read(int fd, void *buf, size_t count)` 
    + reads up to count bytes into buffer from fd
    + **Danger** if `fd = 0` or `buffer < size`
        + `fd = 0` stdin

### `strncpy`

+ `strncpy(char *dest, const char *src, size_t n)`
    + **Danger** when the size of `dest` is the same size as the data being copied in, in this situation `strncpy` will not copy the NULL byte 
    + This leads to out of bounds reads where the data is used in say a print function which reads until a null byte is encounted
+ `strcpy(char *dest, const char *src)`
    + Same as `strncpy` but no max size, more risk of buffer overflows since no max size
    + Copies terminating nullbyte
    + Strings cannot overlap in memory 
    + `dest` must be large enough to hold `src`


### `strcat`

+ `strcat(char *dest, const char *src)`
    + **Danger** when the size of src is not limited or not limited enough for the size of the `dest` buffer being written to, leading to BOF 
+ `strncat(char *dest, const char *src, size_t n)`
    + **Danger** when supplied max size`n` is not appropriate for the `dest` buffer



## Logic Bugs

+ Conditionals around the wrong way
+ Double `||` instead of `&&`
+ defaulting conditions to true and having a vulnerable check e.g. `admin = true`, some check sets to false but can be bypassed
+ No breaks in switch cases
+ No `exits` on critical error
+ Not checking if `malloc` and other functions that deal with memory allocation (that can fail), leads to potential negation of null byte exception handling (last page address `0x0` gets corrupted) which can be exploitable 


### Array out of Bounds Access

+ Using unsanitised or unchecked user input directly as the index to an array read/write operation


```c
char element = elements[atoi(buffer)];
```



## Type Confusions / Overflows

+ `x86` sizes 
    + `byte` -  This is a `8 bit (1 byte)` quantity
      + `0 - 255` unsigned range
    + `word` - A word is two bytes giving us a `16 bit (2 byte)` quantity
      + `0 - 65535` unsigned range
    + `dword` - A double word is a `32 bit (4 byte)` quantity
      + `0 - 4294967295` unsigned range
    + `qword` - A quad word, a `64 bit (8 byte)` quantity
      + `0 - 18446744073709551615` unsigned range


+ `C` [sizes](https://www.tutorialspoint.com/cprogramming/c_data_types.htm)
    + Size is in bytes


| Type     | Size         | Max            | Range (unsigned)                     |
| -------- | ------------ | -------------- |--------------------------------------|
| `char`   | `1`          | `255`          | `-128 - 127`                         |
| `short`  | `2`          | `65,535`       | `-32,768 - 32,767`                   |
| `int`    | `4`          | `65,535`       | `-2,147,483,648 to 2,147,483,647`    |


**Classic Type Overflows (should be caught by gcc)**

```c
char input = atoi(buffer);
uint_8 port;
scanf("%d", &port);
```

**Type Overflow Debugger**

```C
#include <stdio.h>
#include <stdlib.h>

void main(void);
void menu(void);
void sandbox(int choice);

/*
    A poor mans type confusion sandbox for
    dynamic debugging of type overflows.
*/

void
menu(void)
{
    puts("");

    puts("(1) char");
    puts("(2) short");
    puts("(3) integer");
    puts("(4) float");
    puts("(5) unsigned");

    puts("");
}



void
sandbox(int choice)
{
    char character;
    short short_integer;
    int integer;
    unsigned long long_integer;
    float float_number;

    printf(">>> ");

    switch (choice) 
    {
        case 1:
            scanf("%d", &character);
            printf("%d\n", character);
            break;
        case 2:
            scanf("%d", &short_integer);
            printf("%d\n", short_integer);
            break;
        case 3:
            scanf("%lu", &integer);
            printf("%lu\n", integer);
            break;
        case 4:
            scanf("%lf", &float_number);
            printf("%lf\n", float_number);
            break;
        case 5:
            scanf("%llu", &long_integer);
            printf("%llu\n", long_integer);
        default:
            puts("Invalid choice");
            main();
            break;
    }

    getchar();
}


void
main()
{
    menu();
    int choice;

    printf("Choice (1-5): ");
    scanf("%d", &choice);      

    while (1) 
    {
        sandbox(choice);
    }
}
```

## System Vulnerabilities

+ This category refers to vulnerabilities which expose access to the underlying host or could compromise or cause the host system to react in an unsual way

### Arbitary File Read/Write

+ Reading a 'filename' into a buffer but not ensuring that a relative path cannot be supplied / blindly accepting the buffer directly int a filename 

```c
void read_file(int socket, char *action) {
  FILE *file;
  char buf[MAX_LEN];

  int x, y;
  int complete = 0;

  snprintf(buf, MAX_LEN, "./webpath/%s", action);
  file = fopen(buf, "r");

  if (!file) {
    write_socket(socket, FILENOTAVAIL, sizeof(FILENOTAVAIL));
    return;
  }

  while (fgets(buf, MAX_LEN, file)) {
    write_socket(socket, buf, strlen(buf));
  }
  fclose(file);
}

```

+ In the `read_file` function we see a `snprintf(buf, MAX_LEN, "./webpath/%s", action)` which takes in input from the client controlled `action` buffer. The function call is vulnerable because of the way the functions 'output' is used to read the filesystem, via ` file = fopen(buf, "r")`, without performing any validation or truncation of the user supplied input. Dependant on the file system context where the binary executes, an attacker may exploit the vulnerability by performing a path traversal, with some number of `../`, to reach the root of the file system from where they could read known files like `/etc/shadow` (if the binary runs as root, which is likely give it wields sockets) or the users file `/etc/passwd`. 
+ Indeed the attacker as a similar capacity to write by exploiting the identically vulnerable `write_file`, with the difference being that the read in file is opened in write mode, `  file = fopen(buf, "w")`. 

**$PATH and file naming**


```c
static char* get_username(void) {
	static char username[512];
	system("logname > /tmp/better_sudo.tmp");
	FILE* f = fopen("/tmp/better_sudo.tmp","r");
	fgets(username,sizeof username,f);
	/* bug: if there's no newline in better_sudo.tmp; will attempt to write to 0x0 */
	*strchr(username,'\n') = '\0';
	return username;
}
```

+ `logname` is relative to `PATH;` which the user controls. Any program named `logname` in the path will be executed as root. `PATH=/tmp:$PATH; cp /bin/sh /tmp/logname`
+ `/tmp/better_sudo.tmp` is owned by the first user to use `better_sudo;` and they can overwrite it to whatever they wish between the system; command and reading the file
+ `logname` also isn't the right command to use for this (`getpw` is better)

## Race Conditions

//TODO

* Multiple threads accessing / editing same data

**Typical I/O Race Condition**

```c
#define DELAY 10000

int main(void)
{
    char *fn = "/tmp/XYZ";
    char buffer[60];
    FILE *fp;
    
    long nt i;
    /* get user input */
    scanf("%50s", buffer);
    if(!access(fn, W_OK)) {
        // spin
        for (i = 0; i < DELAY; i++) {
            // computational expense
            int a = i^2; 
        }
        fp = fopen(fn, "a+");
        fwrite("\n", sizeof(char), 1, fp);
        fwrite(buffer, sizeof(char), strlen(buffer), fp);
        fclose(fp);
    }
    
    else {
        printf("No perms \n");
    }
    
```


+  If the file `/tmp/xyz` does not exist the program will begin a computationally expensive operation that will delay the opening and writing of the file 
+ In this processing time the attacker can potentially `symlink` "/tmp/xyz" to a file of intrest on the host say `/etc/shadow` 
+ Resulting in the data being scanned 


**Thread Race Condition**

```c
#include<stdio.h>
#include<sys/types.h>
#include<unistd.h>
static void charatatime(char *);
int main(void)
{
    pid_t pid;
    if ((pid = fork()) < 0) {
        printf("fork error");
    }
    
    else if (pid == 0) {
        charatatime("output from child\n");
    }
    
    else {
        charatatime("output from parent\n");
    }
    
    return 0;
}

static void charatatime(char *str)
{
    char *ptr;
    int c;
    setbuf(stdout, NULL); /* set unbuffered */
    for (ptr = str; (c = *ptr++) != 0; )
        putc(c, stdout);
}
```


## Tooling

+ [graudit](https://github.com/wireghoul/graudit)
    + Grep for source auditing
+ [clang static analyser](https://clang-analyzer.llvm.org/)
+ If you can run `gcc` outright or patch out the code until you can you can use 
    + `gcc -Wall <src>.c -o src` which will report trivial errors such as type overflows/underflows and buffer overflows 

## Misc / Tricks
 
+ Sandbox stuff in another `C` file if you are not sure especially with type conversions and null byte overflows
+ Convert static to dynamic analysis where possible, humans are better at it