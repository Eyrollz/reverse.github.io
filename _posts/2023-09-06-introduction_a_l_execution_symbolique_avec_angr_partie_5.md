---
title: Partie 5 - Solutions des exercices
date: 2023-09-06 10:00:00
categories: [Reverse, Introduction à l'exécution symbolique avec angr]
tags: [angr, Exécution symbolique]
author: kabeche
toc: true
---

# Solutions des exercices

Plusieurs exercices ont été proposés dans ce cours. Cette section comporte des solutions pour chacun d'eux. Il est à noter que les manières de résoudre un même exercice peuvent être multiples. Il ne s'agit donc pas de solutions "optimales" mais seulement de solutions qui permettent de résoudre un exercice donné.

> Dans tous les scripts proposés, il est normal que vous n'ayez pas les mêmes adresses car cela dépend en partie de votre compilateur.
> 
> Il suffit de les adapter en fonction de ce que vous avez comme adresses dans le code désassemblé.
{: .prompt-warning }

> Il n'est pas très utile de regarder les solutions aux exercices si vous n'avez pas cherché par vous même à une manière de résoudre l'exercice, vous n'apprendrez pas grand chose ...
{: .prompt-tip }
## Exercice 1 - Introduction

### Objectif
Trouver le bon input de ce programme :
```c++
#include "stdio.h"  
#include "stdlib.h"  
#include "string.h"  
  
unsigned long long algo(unsigned long long arg)  
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
   puts("Give me the key in hexadecimal : ");  
   read(0,key_buffer,16);  
   unsigned long long arg = strtoull(key_buffer,NULL,16);  
   if (algo(arg) == 0xdeadbeefcafebabe)    
   {  
     puts("Win !");  
     return 1337;  
   }    
   else    
   {  
     puts("Loose !");  
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
state_0 = p.factory.blank_state(addr= 0x401245) # Adresse de "push   rbp" dans le "main"  
  
sm = p.factory.simulation_manager(state_0)  
  
def hook_strtoull(state):  
   print("[i] La fonction strtoull a été hookée")  
   state.regs.rax = arg_symb  
  
p.hook(0x4012a7,hook_strtoull,5)  
print("[+] Exploration en Cours ....")  
sm.explore( find = 0x4012cb, avoid = 0x4012e1)  
  
print("[+] Arrivé à destination")  
  
if len(sm.found) == 0:  
       print("[-] Il n'a pas été possible d'atteindre la destination")  
       quit()  
else :  
       print("[+] Détermination de l'input valide")  
  
       # Récupération de l'état qui est arrivé dans le bon bloc  
       found = sm.found[0]  
       # Appel au solveur pour retourner au moins une solution  
       res = found.solver.eval(arg_symb)  
       print("[+] Le bon input est : ",hex(res))
```
### Commentaire

Ce qui posait problème dans ce script était principalement la fonction `strtoull`. Il s'agit d'une fonction qui ressemble à `atoi` mais qui retourne un entier de 64 bits. On l'a donc *hookée* afin qu'angr puisse poursuivre l'exécution sans problème.

Pas besoin de *hook* `puts` et `read` qui sont *hookées* de base par angr.

### Résultat
```
[+] Exploration en Cours ....  

WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing register with an unspecified value. This could indicate unwanted behavior.                                
WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:                
WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state  
WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null                         
WARNING  | 2023-09-16 15:30:04,501 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.                             
WARNING  | 2023-09-16 15:30:04,502 | angr.storage.memory_mixins.default_filler_mixin | Filling register rbp with 8 unconstrained bytes referenced from 0x401245 (main+0x4 in exe (0x401245))                                                                         

[i] La fonction strtoull a été hookée  
[+] Arrivé à destination  
[+] Détermination de l'input valide  
[+] Le bon input est :  0x3133353739515355
```

## Exercice 2 - Lecture de la stack
### Objectif 

Ecrire une fonction`read_from_stack(state,n)` qui affiche les `n` première valeurs ( de 64 bits par ex) sur la stack de l'état `state`.

### Solution

```python
import archinfo  
import angr  
  
def read_from_stack(state, n):  
   stack_pointer = state.regs.rsp  
  
   values = []  
  
   for _ in range(n):  
  
       # Lecture de 8 octets (64 bits)  
       value = state.memory.load(stack_pointer, 8, endness=archinfo.Endness.LE)     
          
       values.append(value)  
  
       # Incrémentation de RSP pour lire la prochaine valeur  
       stack_pointer += 8     
  
   return values  
  
# Programme quelconque  
binary_path = "/bin/true"  
proj = angr.Project(binary_path)  
initial_state = proj.factory.entry_state()  
  
# Lecture des 10 premières valeurs de 64 bits de la pile  
values_on_stack = read_from_stack(initial_state, 5)  
  
for i, value in enumerate(values_on_stack):  
   print(f"Valeur {i + 1}: {value}")
```
### Commentaire

Déjà, merci ChatPGT pour les travaux ;) !

Ensuite, on utilise la lecture en mémoire pour lire les différentes valeurs de 8 octets sur la *stack*.

Le programme `/bin/true` est utilisé ici mais vous pouvez spécifier n'importe quel programme.
### Résultat

```
Valeur 1: <BV64 0x1>  
Valeur 2: <BV64 0x7fffffffffeffc8>  
Valeur 3: <BV64 0x0>  
Valeur 4: <BV64 0x0>  
Valeur 5: <BV64 0x19>
```

## Exercice 3 - Gestion de l'input et output

### Objectif

Tester la gestion de `stdin` en compilant un programme basique en C qui lit, par exemple, 8 octets et vérifie qu'il s'agit du bon mot de passe.

Utiliser ensuite angr afin de trouver le mot de passe automatiquement **sans avoir à *hook*** les fonctions qui lisent depuis `stdin`.

### Programme utilisé

Voici le programme C utilisé pour cet exercice compilé avec `gcc -no-pie main.c -o exe` :

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
   // solution : USQ97531  
   unsigned char key_buffer[8] = {0};  
   puts("Give me the key in hexadecimal : ");  
   read(0,key_buffer,8);  
   if (algo(key_buffer) == 0xdeadbeefcafebabe)    
   {  
     puts("Win !");  
     return 1337;  
   }    
   else    
   {  
     puts("Loose !");  
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

# Utilisation d'un buffer symbolique dans stdin
state_0 = p.factory.blank_state(addr= 0x4011ea,stdin=flag)  
  
sm = p.factory.simulation_manager(state_0)  
  
def is_output_good(state):  
       # Est-ce que "Win !" est présent dans l'output ?  
       output = state.posix.dumps(sys.stdout.fileno())  
       return b'Win !' in output  
  
def is_output_bad(state):  
       # Est-ce que "Loose !" est présent dans l'output ?  
       output = state.posix.dumps(sys.stdout.fileno())  
       return b'Loose !' in output  
  
print("[+] Exploration en Cours ....")  
sm.explore( find = is_output_good, avoid = is_output_bad)  
if len(sm.found) == 0:  
       print("[-] Il n'a pas été possible d'atteindre la destination")  
       quit()  
else :  
       print("[+] Détermination de l'input valide")  
       # Récupération de l'état qui est arrivé dans le bon bloc  
       found = sm.found[0]
       # Conversion en bytes du résultat  
       res = found.solver.eval(flag,cast_to=bytes)  
       print("[+] Le bon input est : ",res.decode())
```

### Commentaire

Les points importants sont les suivants :
- Utilisation d'un *buffer* symbolique dans l'input via `state_0 = p.factory.blank_state(addr= 0x4011ea,stdin=flag) ` 
- Exploration en fonction de l'output et non pas en utilisant des adresses avec `sm.explore( find = is_output_good, avoid = is_output_bad) `

Et au final, aucun *hook* n'a été nécessaire !
### Résultat
```
WARNING  | 2023-09-16 15:03:47,468 | angr.simos.simos | stdin is constrained to 8 bytes (has_end=True). If you are only providing the first 8 bytes instead of the entire stdin, please use stdin=SimFileStream(name='stdin', content=your_first_n_bytes, has_end=False).                                                                                             

[+] Exploration en Cours ....  

WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing register with an unspecified value. This could indicate unwanted behavior.                        
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:                
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state  
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null                         
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.                              
WARNING  | 2023-09-16 15:03:47,479 | angr.storage.memory_mixins.default_filler_mixin | Filling register rbp with 8 unconstrained bytes referenced from 0x4011ea (PLT.__cxa_finalize+0x19a in exe (0x11ea))

[+] Détermination de l'input valide  
[+] Le bon input est :  USQ97531
```

## Exercice 4 - Gestion des fichiers
### Objectif
Le programme suivant lit depuis un fichier des données afin de les valider ou non. A vous de trouver le contenu adéquat grâce à angr !

Cet exercice vous permettra de comprendre le fonctionnement global des `SimFiles`. 

```c++
#include <stdio.h>  
#include <stdint.h>  
  
int main() {  
   FILE *file = fopen("mdp.bin", "rb");   
   if (file == NULL) {  
       perror("Erreur lors de l'ouverture du fichier");  
       return 1;  
   }  
  
   uint64_t win_value = 0xdeadbeefcafebabe;  
   uint64_t read_value;  
  
   // Lecture de 8 octets depuis le fichier  
   size_t bytes_read = fread(&read_value, 8, 1, file);  
   if (bytes_read != 1) {  
       perror("Erreur lors de la lecture du fichier");  
       fclose(file);  
       return 1;  
   }  
  
   // Fermeture du fichier  
   fclose(file);  
  
   if (read_value == win_value) {  
       printf("Win\n");  
   } else {  
       printf("Loose\n");  
   }  
  
   return 0;  
}
```

Pour le compiler : `gcc -no-pie main.c -o exe`.
**Indice** : aucun *hook* n'est nécessaire pour la réussite de cet exercice ;) !

### Solution
```python
import angr  
import claripy    
  
p = angr.Project("./exe")  
  
data = claripy.BVS('mdp', 8 * 8)  
simfile = angr.storage.SimFile("mdp.bin", content=data)  
  
state = p.factory.entry_state(addr = 0x4011E9, fs={ "mdp.bin" : simfile})  
  
sm = p.factory.simulation_manager(state)  
sm.explore(find=0x4012b9, avoid=0x4012c7)  
  
found = sm.found[0]  
print("[+] Les données à utiliser sont : ",found.solver.eval(data, cast_to=bytes))
```

### Commentaire
1. On crée un `SimFile` contenant des données symboliques
2. On insère le `SimFile` dans l'état initial (son *filesystem*) avec `fs={ "mdp.bin" : simfile}`
3. On explore jusqu'à arriver à destination

> On aurait également pu utiliser l'*output* pour explorer au lieu d'utiliser des adresses en dur.
{: .prompt-tip }
### Résultat
```
[+] Les données à utiliser sont :  b'\xbe\xba\xfe\xca\xef\xbe\xad\xde'
```