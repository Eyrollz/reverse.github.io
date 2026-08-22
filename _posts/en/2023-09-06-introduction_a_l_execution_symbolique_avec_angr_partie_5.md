---
title: Part 5 - Exercise solutions
date: 2026-08-01 10:00:00
categories: [Reverse, Introduction to symbolic execution with angr]
tags: [angr, symbolic execution]
author: kabeche
toc: true
---

# Exercise solutions

Several exercises were proposed in this course. This section contains solutions for each of them. Note that there can be multiple ways to solve the same exercise. These are therefore not "optimal" solutions, but only solutions that make it possible to solve a given exercise.

> In all the proposed scripts, it is normal if you do not have the same addresses, because this partly depends on your compiler.
>
> You just need to adapt them according to the addresses you have in the disassembled code.
{: .prompt-warning }

> It is not very useful to look at the exercise solutions if you have not tried to find a way to solve the exercise yourself, you will not learn much 😅 ...
{: .prompt-tip }

## Exercise 1️⃣ - Introduction

### Goal

Find the correct input for this program:

```c++
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

unsigned long long hash(unsigned long long arg)
{
  unsigned long long result = 0;
  unsigned char x =0;
  unsigned long long temp =0;

  unsigned long long key =0xef9e8bd8f3afe9eb;
  for (int i =0;i<8;i++)
  {
    x = (arg >> (i*8)) &0xff;
    switch(x % 2)
    {
            case 0:
                temp = 0xff;
                break;
            case 1:
                temp = x ^ (unsigned char)((key >> (i*8)) &0xff);
                break;

      }

      result = result | (temp << (i*8));
  }
    return result;
}
int main()
{
    char key_buffer[16] = {0};
    puts("Give me the key in hexadecimal: ");
    read(0,key_buffer,16);
    unsigned long long arg = strtoull(key_buffer,NULL,16);
    if (hash(arg) == 0xdeadbeefcafebabe)
    {
      puts("Win !");
      return 1337;
    }
    else
    {
      puts("Lose !");
      return -1;
    }
}
```

### Solution

```python
import angr
import claripy

p = angr.Project("./exe")

arg_symb = claripy.BVS('input', 8*8)
state_0 = p.factory.blank_state(addr= 0x401245) # Address of "push   rbp" in "main"

sm = p.factory.simulation_manager(state_0)

def hook_strtoull(state):
   print("[i] The strtoull function has been hooked")
   state.regs.rax = arg_symb

p.hook(0x4012a7,hook_strtoull,5)
print("[+] Exploration in progress ....")
sm.explore( find = 0x4012cb, avoid = 0x4012e1)

print("[+] Arrived at destination")

if len(sm.found) == 0:
       print("[-] It was not possible to reach the destination")
       quit()
else :
       print("[+] Determining the valid input")

       # Retrieve the state that reached the correct block
       found = sm.found[0]
       # Call the solver to return at least one solution
       res = found.solver.eval(arg_symb)
       print("[+] A correct input is: ",hex(res))
```

### Comment

The main problem in this script was the `strtoull` function. It is a function that resembles `atoi`, but returns a 64-bit integer. So we hooked it so that angr could continue execution without any problem.

No need to *hook* `puts` and `read`, which are properly *hooked* by angr by default.

### Result
```
[+] Exploration in progress ....

WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing register with an unspecified value. This could indicate unwanted behavior.
WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.
WARNING  | 2023-09-16 15:30:04,502 | angr.storage.memory_mixins.default_filler_mixin | Filling register rbp with 8 unconstrained bytes referenced from 0x401245 (main+0x4 in exe (0x401245))

[i] The strtoull function has been hooked
[+] Arrived at destination
[+] Determining the valid input
[+] A correct input is:  0x3133353739515355
```

## Exercise 2️⃣ - Reading the stack

### Goal

Write a function `read_from_stack(state,n)` that displays the first `n` values (64-bit values, for example) on the stack of the `state` state.

### Solution

```python
import archinfo
import angr

def read_from_stack(state, n):
   stack_pointer = state.regs.rsp

   values = []

   for _ in range(n):

       # Read 8 bytes (64 bits)
       value = state.memory.load(stack_pointer, 8, endness=archinfo.Endness.LE)

       values.append(value)

       # Increment RSP to read the next value
       stack_pointer += 8

   return values

# Random program
binary_path = "/bin/true"
proj = angr.Project(binary_path)
initial_state = proj.factory.entry_state()

# Read the first 10 64-bit values from the stack
values_on_stack = read_from_stack(initial_state, 5)

for i, value in enumerate(values_on_stack):
   print(f"Value {i + 1}: {value}")
```

### Comment

First of all, thanks ChatGPT for the work ;)!

Then, we use memory reading to read the different 8-byte values on the stack.

The `/bin/true` program is used here, but you can specify any program.

### Result

```
Value 1: <BV64 0x1>
Value 2: <BV64 0x7fffffffffeffc8>
Value 3: <BV64 0x0>
Value 4: <BV64 0x0>
Value 5: <BV64 0x19>
```

## Exercise 3️⃣ - Handling input and output

### Goal

Test `stdin` handling by compiling a basic C program that reads, for example, 8 bytes and checks whether it is the correct password.

Then use angr to find the password automatically **without having to hook** the functions that read from `stdin`.

### Program used

Here is the C program used for this exercise, compiled with `gcc -no-pie main.c -o exe`:

```c++
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

unsigned long long algo(unsigned char *arg)
{
 unsigned long long result = 0;
 unsigned char x =0;
 unsigned long long temp =0;

 unsigned long long key =0xef9e8bd8f3afe9eb;
 for (int i =0;i<8;i++)
 {
   x = arg[i] ;
   switch(x % 2)
   {
           case 0:
               temp = 0xff;
               break;
           case 1:
               temp = x ^ (unsigned char)((key >> (i*8)) &0xff);
               break;

     }

     result = result | (temp << (i*8));
 }
   return result;
}
int main()
{
   // solution: USQ97531
   unsigned char key_buffer[8] = {0};
   puts("Give me the key in hexadecimal: ");
   read(0,key_buffer,8);
   if (algo(key_buffer) == 0xdeadbeefcafebabe)
   {
     puts("Win !");
     return 1337;
   }
   else
   {
     puts("Lose !");
     return -1;
   }
}
```

### Solution

```python
import angr
import sys
import claripy

p = angr.Project("./exe")
flag = claripy.BVS('flag', 8*8)

# Use a symbolic buffer in stdin
state_0 = p.factory.blank_state(addr= 0x4011ea,stdin=flag)

sm = p.factory.simulation_manager(state_0)

def is_output_good(state):
       # Is "Win !" present in the output?
       output = state.posix.dumps(sys.stdout.fileno())
       return b'Win !' in output

def is_output_bad(state):
       # Is "Lose !" present in the output?
       output = state.posix.dumps(sys.stdout.fileno())
       return b'Lose !' in output

print("[+] Exploration in progress ....")
sm.explore( find = is_output_good, avoid = is_output_bad)
if len(sm.found) == 0:
       print("[-] It was not possible to reach the destination")
       quit()
else :
       print("[+] Determining the valid input")
       # Retrieve the state that reached the correct block
       found = sm.found[0]
       # Convert the result to bytes
       res = found.solver.eval(flag,cast_to=bytes)
       print("[+] The correct input is: ",res.decode())
```

### Comment

The important points are the following:
- Using a symbolic *buffer* in the input via `state_0 = p.factory.blank_state(addr= 0x4011ea,stdin=flag) `
- Exploring based on the output and not by using addresses with `sm.explore( find = is_output_good, avoid = is_output_bad) `

And in the end, no hook was necessary!

### Result

```
WARNING  | 2023-09-16 15:03:47,468 | angr.simos.simos | stdin is constrained to 8 bytes (has_end=True). If you are only providing the first 8 bytes instead of the entire stdin, please use stdin=SimFileStream(name='stdin', content=your_first_n_bytes, has_end=False).

[+] Exploration in progress ....

WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing register with an unspecified value. This could indicate unwanted behavior.
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | Filling register rbp with 8 unconstrained bytes referenced from 0x4011ea (PLT.__cxa_finalize+0x19a in exe (0x11ea))

[+] Determining the valid input
[+] The correct input is:  USQ97531
```

## Exercise 4️⃣ - Handling files

### Goal

The following program reads data from a file in order to validate it or not. It is up to you to find the appropriate content using angr!

This exercise will help you understand the overall functioning of `SimFiles`.

```c++
#include <stdio.h>
#include <stdint.h>

int main() {
    FILE *file = fopen("password.bin", "rb");
    if (file == NULL) {
         perror("Error while opening the file");
         return 1;
    }

    uint64_t win_value = 0xdeadbeefcafebabe;
    uint64_t read_value;

    // Read 8 bytes from the file
    size_t bytes_read = fread(&read_value, 8, 1, file);
    if (bytes_read != 1) {
         perror("Error while reading the file");
         fclose(file);
         return 1;
    }

    // Close the file
    fclose(file);

    if (read_value == win_value) {
         printf("Win\n");
    } else {
         printf("Lose\n");
    }

    return 0;
}
```

To compile it: `gcc -no-pie main.c -o exe`.
**Hint**: no hook is necessary to complete this exercise ;)!

### Solution

```python
import angr
import claripy

p = angr.Project("./exe")

data = claripy.BVS('password', 8 * 8)
simfile = angr.storage.SimFile("password.bin", content=data)

state = p.factory.entry_state(addr = 0x4011E9, fs={ "password.bin" : simfile})

sm = p.factory.simulation_manager(state)
sm.explore(find=0x4012b9, avoid=0x4012c7)

found = sm.found[0]
print("[+] The data to use is: ",found.solver.eval(data, cast_to=bytes))
```

### Comment

1. We create a `SimFile` containing symbolic data
2. We insert the `SimFile` into the initial state (its *filesystem*) with `fs={ "password.bin" : simfile}`
3. We explore until we reach the destination

> We could also have used the *output* to explore instead of using hardcoded addresses.
{: .prompt-tip }

### Result

```
[+] The data to use is:  b'\xbe\xba\xfe\xca\xef\xbe\xad\xde'
```