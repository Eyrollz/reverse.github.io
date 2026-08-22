---
title: Part 3 - Basic features (again)
date: 2026-08-03 10:00:00
categories: [Reverse, Introduction to symbolic execution with angr]
tags: [angr, symbolic execution]     # TAG names should always be lowercase
author: kabeche
toc: true
---
## Using hooks like a pro 💪

If your memory is not too short, you should remember how we used a hook. As a reminder, we did something like this:

```python
p.hook(0x40113f, hook_atoi,5)
```

This allowed us to *hook* the `call atoi` instruction (5 bytes in size) so that we could **modify its behavior through Python**. However, there are other use cases where we can use *hooks*.

For example, you must have noticed that when a program uses `puts` or `printf`, we never see the displayed string directly. Let's try to modify this behavior with a *hook* using `SimProcedures` so that we always display the content of `puts`.

### Defining your own *hook* with `SimProcedure`

`SimProcedures` allow us to do **advanced *hooking*** by, for example, easily accessing the arguments of the *hooked* function.

Let's make a simple C program that performs successive calls to `puts`:

```c++
#include <stdio.h>

int main()
{
     puts("How");
     puts("are");
     puts("you");
     puts("?");
     return 0;
}
```

If we run the program with angr until the `return`, we will not see the strings in our terminal (unless we fiddle with `state.posix.dumps(sys.stdout.fileno())` to access the *output*).

Before dumping all the code in question, let's analyze the *hook* code snippet together so we can understand it properly:

```python
class MyPuts(angr.SimProcedure):
     def run(self, addr_str):
          #(...)

p.hook_symbol('puts', MyPuts())
```

> In the arguments of `hook` and `hook_symbol`, when a class derived from `SimProcedure` is used, you absolutely need to include the parentheses, otherwise angr might get ... angry 🙃
{: .prompt-warning }

To use `SimProcedures`, you must always declare your derived class like this: `MyClass(angr.SimProcedure)`. This then gives access to certain **predefined functions** such as `run`, which is the function executed when our *hook* is triggered.

Now, we need to fill in this `run` function. What are we going to put in it?

> Well, that's easy, we just do `print(addr_str)` 🙄
{: .prompt-info }

Nice try, but that will not work! Actually, you need to see the `addr_str` argument as the `puts` argument in C. Now, the argument of `puts` is a string, more precisely, **a pointer to a memory area** containing characters whose end is indicated by a null byte.

So we will need to tinker a little to retrieve the string at the address `addr_str`. Nothing too nasty, a `for` loop and we are done:

```python
class MyPuts(angr.SimProcedure):
    def run(self, addr_str):
        string = ""
        # Retrieve the string
        # by reading byte by byte
        for i in range(1000) :
              val = self.state.memory.load(addr_str+i,1).concrete_value
              # End of the string
              if val == 0 :
                 break

              string += chr(val)
        # Display the string
        print(string)

        return 0
```

A few remarks:

- We have access to the current state via `self.state`
- We use the famous `state.memory.load` to read memory and retrieve the data *bytes* at the address `addr_str[i]` in the loop
- When we reach the null byte, it is the end of the string
- `range(1000)` is used as a safeguard to avoid looping forever

The final script is this one (be careful to **modify the address** of the `return` to match your program):

```python
import angr

# Initialize the project, initial state ...
p = angr.Project("./exe")
main = p.loader.find_symbol("main")
state_0 = p.factory.blank_state(addr= main.rebased_addr)
sm = p.factory.simulation_manager(state_0)

class MyPuts(angr.SimProcedure):
     def run(self, addr_str):
          string = ""
          # Retrieve the string
          for i in range(1000) :
               val = self.state.memory.load(addr_str+i,1).concrete_value
               # End of the string
               if val == 0 :
                         break

               string += chr(val)
          # Display the string
          print(string)

          return 0

p.hook_symbol('puts', MyPuts())

# Address of the 'return'
sm.explore( find = 0x401193)
```

By running this script, we do see the expected strings in the terminal:

```
How
are
you
?
```

### Defining a hook with a decorator

It is possible to use a Python decorator to define a *hook*. For example, for the *hook* we have already seen:
```python
p.hook(0x40113f, hook_atoi,5)
```

It is possible to do:
```python
@project.hook(0x40113f, length=5)
def hook_atoi(state):
	# (...)
```

This makes it possible to define the *hook* **at the same time** as the associated function. It is a bit prettier and more readable when reading the script.

It is possible to define several *hooks* by using several decorators around the associated *hook*. This is useful when a *hooked* function is called many times in the program:

```python
@project.hook(0x40113f, length=5)
@project.hook(0x409795, length=5)
def hook_atoi(state):
	# (...)
```

### A story of symbols

Hooking libc functions is easy because:
- either angr already does it
- or we have access to the symbol (and therefore we can retrieve the function address through its name), whether the program is stripped or not

However, when the program is **stripped** (the symbols of internal functions are removed), we **no longer have access** to the names of internal functions. Even `main` is no longer directly accessible through its symbol with `main = p.loader.find_symbol("main")` 😢.

In such a situation, when we want to *hook* a program function `fun_prgrm`, we have two ways to do it:

- Either we know exactly where this function is called, and we just need to *hook* all instructions of the type: `call fun_prgrm`
- Or we do not know where this is done, and we will need to *hook* the **entire** function

We have already faced the first case, and we know how to handle it. But what should we do if we end up in the second case?

In the second case, there are two ways to do it:

1. **Use a classic hook**: this is **tedious** because you need to calculate the size of the function, exit the function yourself by modifying `rip` with the appropriate value 🥱 ...
2. **Use a class derived from** `SimProcedure`: this is the **simplest** method because we will not need to calculate the size of the function, nor even return ourselves; angr already does it for us

#### Using a classic hook

The first method can be interesting when you want to modify the behavior of a **large block of code** that is not a called function. For example, if you manage to identify a piece of code that does anti-debug detection, *sleep*, or is not very interesting, you can simply *hook* it with a function that **does nothing** (this amounts to "NOPing" the whole piece of code).

Example:

```python
# NOP several instructions
@p.hook(start_address, length=total_size_of_instructions)
def nop(state):
	print("NOP")
```

#### Using a class derived from `SimProcedure`

The only condition for using this method is knowing where the function you want to *hook* is located (let's call it `fun_prgrm`). Then we use a class derived from `SimProcedure`, and it will take care of returning properly all by itself.

For example, if `fun_prgrm` is located at `0x401149`, we can do:

```python
class MyFunc(angr.SimProcedure):
	def run(self):
		print("'fun_prgrm' hooked")
		# (...)
		return

p.hook(0x401149, MyFunc())
```


## The limits of angr

After seeing the main features offered by angr, you are probably thinking that you will finally be able to **destroy** all crackmes and **reverse engineer any program much more easily**. Well, unfortunately, it is not that simple because angr still has quite a few limitations 🫣 ...

### Execution engine written in Python 🐍

One of angr's **major weaknesses** compared to other symbolic execution tools such as [Triton](https://github.com/JonathanSalwan/Triton) or [Binsec](https://github.com/binsec/binsec) is that it is written entirely in **Python**.

Thus, even the execution engine is written in Python, unlike other tools where Python is simply a wrapper to make them easier to use.

Python is nice, it is simple, but wow is it slow ^^'!

### Path explosion 💥

We briefly talked about it, but this is **one of the biggest problems** in symbolic execution. It does not only concern angr, but any symbolic execution engine.

Let's take a concrete example to see how angr will react during a path explosion.

Here is the C code we will use:

```c++
#include <stdio.h>

int one()
{
	return 1;
}
int zero()
{
	return 0;
}

int main()
{

	unsigned char data[16];
	printf("Enter 16 bytes of data: ");
	fread(data, sizeof(unsigned char), 16, stdin);

	for (int i = 0; i < 16; i++)
	{
		for (int j = 7; j >= 0; j--)
		{
			if ((data[i] >> j) & 1)
			{
				one();
			}
			else
			{
				zero();
			}
		}
	}

	return 0;
}
```

This is fairly simple code, and its behavior should be easy for you to understand.

Let's compile it with `gcc main.c -o exe`. Now, let's run angr on the program by giving it an unreachable address during exploration:

```python
import angr
import IPython
import claripy
import os
import signal

# Code to open IPython
# with Ctrl+C
def kill():
	current_pid = os.getpid()
	os.kill(current_pid, signal.SIGTERM)

def sigint_handler(signum, frame):
	print('Kill with: kill()')
	IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)

p = angr.Project("./exe")
flag = claripy.BVS('flag', 16*8)

# We use 'rebased_addr' because the program is compiled
# with PIE protection
main = p.loader.find_symbol("main")
state_0 = p.factory.blank_state(addr= main.rebased_addr,stdin=flag)
sm = p.factory.simulation_manager(state_0)

# Unreachable address
print("Exploration in progress from main")
sm.explore( find = 0xdeadbeef)
```

A few remarks:

- The program we just compiled is not *stripped*, so we have access to all symbols, including the `main` symbol via `p.loader.find_symbol("main")`
- Since we compiled the program without the `-no-pie` option, `main` is at the *offset* `0x11a7`. But during execution, it will be executed at a random address of the type: `random_base_address + 0x11a7`, for example: `0x00005555555551af`. Thus, we use `main.rebased_addr` so we do not have to worry about PIE
- We insert the piece of code that opens IPython with `Ctrl+C`; this will be useful to us!

When launching the Python script, we see that it consumes more and more memory. Initially, we have:

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/first.png)

Then after a few seconds / minutes of execution:

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/sec.png)

We can see that the script consumes **a huge amount of memory**, and since we do not want the PC to end up *freezing* 🥶, we use the deadly weapon: Ctrl+C 🔫.

An IPython terminal then opens and we can analyze what is happening. Let's try to see what the simulation manager contains, which, as a reminder, manages all the states.

![](/assets/images/introduction_a_l_execution_symbolique_avec_angr/actives.png)

We see that **1410 states are active**, which is **huge**! Already, when you have more than a hundred, you should start asking questions, but here it is way too much!

I recommend ending the script by entering `kill()` in the IPython terminal to free the gigabytes of RAM occupied by the script.

This example lets you understand the main limitation of symbolic execution through **path explosion**.

### External libraries

Another weakness of angr is that it **handles somewhat complex libraries poorly**. For libc, some functions like `printf`, `read`, etc., it knows how to handle. But functions like those from the Windows API are harder for it 🤕.

As a result, when analyzing a Windows program with angr (for example, *malware*), you will need to *hook* quite a few functions so that the script does not go off the rails.

This does not mean that angr cannot run on a Windows program, it just means that you will need to be **more careful** and perform more analysis on the code beforehand before starting a script with angr.

Rest assured, angr is not ONLY useful for solving crackmes. It can be used to deobfuscate certain programs. In this regard, we can mention the deobfuscation of [switch tables for VM Protect](https://whereisr0da.github.io/blog/).

### When should you use angr?

To conclude, I suggest listing the cases where it can be interesting/easy to use angr and, *a contrario*, the cases where it is not necessarily the best idea.

Obviously, this is a fairly subjective list, and just because we classified a case among those where you should avoid using angr does not mean it is an absolute truth.

Ideally, you should look case by case at the expected objective and the way the binary (program, firmware ...) to analyze is designed.

#### Favorable cases ✅

- **A crackme** that uses a fairly linear algorithm with simple operations (xor, add, sub ...)
- **A Linux program**: yes, angr has a bit more trouble with Windows programs (especially the libraries used)
- **A piece of assembly**: this can be a function or simply a piece of disassembled code whose behavior you want to understand. angr can indeed load assembly directly and execute it.
- **Classic deobfuscation**: know that it is possible to effectively deobfuscate a program with angr. This may require advanced notions, but angr has a range of tools that, when used together, can allow you to deobfuscate a program. That said, we are talking here about classic obfuscation (linear switch table, opaque predicates, MBA ...) and not advanced obfuscation (non-linear switch tables, need to execute dynamically ...)

#### Unfavorable cases ⚠️

- **Windows programs**: see the reason above. Obviously, this does not mean that it is impossible to use angr on *malware* (and it is sometimes useful, by the way), but it just means you will need to pay attention to how you configure angr.
- **A program that calls external functions too often**: typically Windows programs that make 1000 calls to Windows API functions
- **Heavily obfuscated programs** with very advanced obfuscation
- **Programs that use state-of-the-art crypto** (angr is not going to break AES anytime soon :) )
