---
title: Partie 23 - Exploiter un binaire par ROP - SROP et JOP (4/6)
date: 2026-04-16 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter un binaire par ROP : SROP et JOP (4/6)

Dans ce chapitre, nous allons nous intéresser à quelques techniques d'exploitation qui sont **proches du ROP** et qui peuvent être utilisées dans certains contextes :

| Technique | Signification                  | Résumé                                                                                                        | Quand l'utiliser ?                                                        |
| --------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **SROP**  | Sigreturn-Oriented Programming | Contourner l'appel système `sigreturn` afin de contrôler l'exécution du programme                             | Présence d'instructions `syscall`/`int 0x80`, **libc** inaccessible, etc. |
| **JOP**   | Jump-Oriented Programming      | Utiliser des instructions de sauts pour contrôler l'exécution du programme                                    | Quand le ROP n'est pas possible 🙄                                        |
| **BROP**  | Blind ROP                      | Technique permettant de faire du ROP "à l'aveugle" sur un programme distant dont on ne dispose pas du binaire | Programme distant dont on ne dispose pas du binaire                       |

Ces techniques sont généralement **très dépendantes du contexte** et, honnêtement, il n’est pas indispensable de toutes les maîtriser. Retenez simplement que ce chapitre vous fournit **les informations nécessaires à leur mise en œuvre**.

Étant donné leur caractère assez **niche**, nous nous concentrerons ici sur la partie **théorique**.

## SROP (ou Sigreturn-Oriented Programming)

Le **SROP** est une [technique d'exploitation](https://www.ieee-security.org/TC/SP2014/papers/FramingSignals-AReturntoPortableShellcode.pdf) basée sur la réutilisation de code, mais dans une moindre mesure que le ROP. Elle consiste à forger une structure `rt_sigframe` à donner en paramètre à l'appel système [sigreturn](https://man.openbsd.org/sigreturn.2), d'où le nom de cette technique 🤓.

Cette technique peut être très intéressante dans le cas où il n'est pas possible d'accéder à la **libc** et que l'on arrive à trouver l'adresse d'une instruction `syscall` ou `int 0x80`.

### Conditions préalables

Bien que très puissant, quelques conditions sont à satisfaire avant de réaliser du **SROP** :

- **contrôler les** `N` **premiers octets** de la pile en ayant la possibilité d'insérer des octets nuls ;
- **contrôler** `eax` / `rax` afin de pouvoir y mettre le numéro de l'appel système `sigreturn` ;
- **trouver l'adresse d'un gadget** `syscall`/`int 0x80`
- **contrôler** `rip`/`eip`.

> `N` est la taille de la structure `rt_sigframe` en octets. S'il n'est pas possible d'avoir **exactement** `N` octets lors du dépassement de mémoire, il faudra **au moins** pouvoir contrôler les principaux registres dont nous aurons besoin.
> {: .prompt-tip }

### Fonctionnement global

L'ingéniosité de cette technique réside dans le fait de contourner l'utilisation de l'appel système `sigreturn` afin **d'exécuter un autre appel système**, par exemple `execve`.

L'objectif de `sigreturn` est de permettre à un gestionnaire de signal de ne pas se préoccuper de rétablir le contexte d'exécution tel qu'il l'était avant de traiter le signal. De ce fait, en utilisant `sigreturn`, c'est le noyau qui s'occupe de **restaurer le contexte d’exécution** à partir de la **sauvegarde** qu'il a faite ... **sur la pile** !

Et vous savez quoi ? Peu importe l'architecture, 32 bits ou 64 bits, la structure `rt_sigframe`, qui contient la sauvegarde du contexte, est toujours **sauvegardée dans la pile** 😏. Ce qui signifie qu'avec un dépassement de mémoire sur la pile, nous pourrons contrôler le contenu de cette structure.

> Si vous souhaitez approfondir le concept de **signal** en programmation C, vous pouvez jeter un œil à [ce cours](http://tvaira.free.fr/os/cours-sys-signaux.pdf).
{: .prompt-tip }

L'idée va donc être de forger la structure `rt_sigframe` de manière à :

- **charger les registres** utilisés comme arguments des appels système avec les **valeurs adéquates** ;
- mettre **la valeur adéquate dans** `eax`/`rax` pour l'appel système final ;
- mettre l'adresse de l'instruction `int 0x80`/`syscall` dans l'endroit où est censé être sauvegardé `eip`/`rip`.

De la sorte, `sigreturn` va se charger, pour nous, de réaliser n'importe quel appel système, merci pour les travaux 😎 !

> Cette technique ressemble sur certains points à [l'utilisation de la fonction setcontext](/posts/exploitation_de_la_heap_partie_12/#setcontext) de la **libc**. Nous en reparlerons dans un chapitre dédié à l'exploitation dans le tas.
{: .prompt-tip }

### La structure `rt_sigframe`

Tout d'abord il faut savoir que **le contenu** et **la taille** de cette structure dépend de l'architecture utilisée. Vous imaginez bien que sauvegarder des registres de 32 bits ne prend pas la même place que sauvegarder des registres de 64 bits.

Intéressons-nous à la **version 64 bits**. De toute manière, la version 32 bits suit le **même principe** et les deux sont définies dans [ce fichier](https://elixir.bootlin.com/linux/v6.17.3/source/arch/x86/include/asm/sigframe.h).

Voici sa définition :

```cpp
struct rt_sigframe {
	char __user *pretcode;
	struct ucontext uc;
	struct siginfo info;
};
```

En descendant d'un cran :

```cpp
struct rt_sigframe {
	char __user *pretcode;
	struct ucontext uc 
		{
			unsigned long	  uc_flags;
			struct ucontext  *uc_link;
			stack_t		  uc_stack;
			struct sigcontext uc_mcontext;
			sigset_t	  uc_sigmask;	
		};
	struct siginfo info;
};
```

Et en descendant encore d'un cran :

![](/assets/images/introduction_au_pwn/mjordan.gif)

C'est bon j'ai compris j'arrête 🥲. Et puis, ce qui nous intéresse, c'est ce que ça donne en mémoire, c'est-à-dire ceci :

![](/assets/images/introduction_au_pwn/struct_sigreturn.png)
[source](https://www.ieee-security.org/TC/SP2014/papers/FramingSignals-AReturntoPortableShellcode.pdf)

Imaginez prendre le contrôle de cette structure et avoir la possibilité de modifier arbitrairement tous ces registres dont `rip` 🤤!

### Exploiter cette structure

> En fait, il va falloir utiliser le *buffer overflow* pour forger toutes ces valeurs sur la pile et faire croire au programme, en exécutant l'appel système `sigreturn`, qu'il doit rétablir le contexte ?
{: .prompt-info }

C'est exactement ça ! La seule difficulté consiste à se rappeler la position de chaque registre dans la structure. Enfin, "difficulté" on se comprend, car **pwntools** permet de **forger cette structure**, nous verrons comment plus tard.

Voici comment exploiter un dépassement mémoire avec du **SROP** (ici en 64 bits) :

![](/assets/images/introduction_au_pwn/schema_srop_bis.png)

1. nous nous plaçons au moment où le dépassement de mémoire est terminé. A partir de maintenant la chaîne SROP débute. La structure `rt_sigframe` est en 🔵, en dessous de l'adresse de l'instruction `syscall` ;
2. tout d'abord, il va falloir trouver et exécuter un gadget qui chargera la valeur `0xf` dans `rax`, étant donné qu'il s'agit du numéro de l'appel système `sigreturn`. Ce gadget 🔴 peut être de différent type, par exemple, un `pop rax ; ret` fera l'affaire ;
3. l'appel système `sigreturn` est exécuté avec la structure forgée `rt_sigframe` dans la pile. Les valeurs les plus intéressantes à contrôler sont en gras, notamment `rdi`, `rsi` et `rdx` pour les arguments du prochain appel système à exécuter. `rax` pour y mettre le numéro du prochain appel système, ici `execve`. Enfin, `rip` afin d'exécuter immédiatement à la sortie de `sigreturn` le prochain appel système ;
4. étant donné que `sigreturn` s'est gentiment chargé de restaurer le contexte d'exécution avec les valeurs que nous avons préalablement choisies, la prochaine exécution de l'instruction `syscall` implique l'appel de `execve("/bin/sh", NULL, NULL)`.

Évidemment, si l’on veut invoquer `execve`, il faut en outre pouvoir écrire la chaîne `"/bin/sh"` (ou la trouver en mémoire) à une adresse connue à l’avance.

Pour ce qui est de la valeur de `eflags` et `cs/gs/fs` dans `rt_sigframe` il y a deux possibilités pour avoir des **valeurs cohérentes** :

- soit mettre les valeurs trouvées via **gdb** au moment où `sigreturn` va être exécuté ;
- ou bien laisser **pwntools** remplir ces valeurs pour nous 😇.

### Construire une chaîne de SROP avec pwntools

#### 64 bits

Construire des chaînes de ROP comme des pros, vous savez tous le faire à présent 😉. Ainsi, je ne doute pas de votre capacité à vous débrouiller pour trouver un gadget ou une astuce pour mettre la valeur `0xf` (`sigreturn`) dans `rax`. 

C'est pourquoi nous allons seulement nous intéresser à la génération d'une structure `rt_sigframe` grâce à **pwntools** et voir comment l'ajouter en tant qu'octets dans notre *payload* final. Ainsi, nous pourrons nous en servir comme modèle en cas de besoin. La voici :

```python
from pwn import *

context.arch = 'amd64'
io = process("./exe")

# Ces valeurs sont a adapter
syscall = 0x400123     # Adresse de l'instruction `syscall`
addr_bin_sh = 0x400213
bourrage = 40 

# Creation de la structure `rt_sigreturn`
frame = SigreturnFrame()
frame.rax = int(constants.SYS_execve)  # 0x3b
frame.rdi = addr_bin_sh                # parametre n°1
frame.rsi = 0                          # parametre n°2
frame.rdx = 0                          # parametre n°3
frame.rip = syscall

payload = b"A" * bourrage
#payload += ...            # Mettre `constants.SYS_rt_sigreturn` dans `rax`
payload += p64(syscall)    # Appel systeme `sigreturn`
payload += bytes(frame)    # Structure `rt_sigframe`

"""
io.send(payload)
(...)
"""
```

On peut même afficher le contenu de `frame` en utilisant **IPython** :

```
In [5]: frame
Out[5]:
{'uc_flags': 0,
 '&uc': 0,
 'uc_stack.ss_sp': 0,
 'uc_stack.ss_flags': 0,
 'uc_stack.ss_size': 0,
 'r8': 0,
 'r9': 0,
 'r10': 0,
 'r11': 0,
 'r12': 0,
 'r13': 0,
 'r14': 0,
 'r15': 0,
 'rdi': 287454020,
 'rsi': 0,
 'rbp': 0,
 'rbx': 0,
 'rdx': 0,
 'rax': 59,
 'rcx': 0,
 'rsp': 0,
 'rip': 2864434397,
 'eflags': 0,
 'csgsfs': 51,
 'err': 0,
 'trapno': 0,
 'oldmask': 0,
 'cr2': 0,
 '&fpstate': 0,
 '__reserved': 0,
 'sigmask': 0}
```

Nous remarquons que **pwntools** s'est chargé de mettre une valeur dans `csgsfs` afin que la restauration du contexte d'exécution ne fasse pas planter le programme.

#### 32 bits

Comme cela a été précédemment mentionné, le **SROP** en 32 bits suit le même principe qu'en 64 bits, les seules différences sont :

- les registres ont une taille de 32 bits (merci Sherlock 🕵️‍♂️) ;
- l'instruction d'appel système est `int 0x80` ;
- la convention d'appel est `ebx`, `ecx` et `edx` au lieu de `rdi`, `rsi` et `rdx` ;
- l'agencement de `rt_sigreturn` est un peu différent.

Ci-dessous, le script pour la **version 32 bits** :

```python
from pwn import *

context.arch = 'i386'
io = process("./exe")

# Ces valeurs sont a adapter
int_0x80 = 0x400123    # Adresse de l'instruction `int 0x80`
addr_bin_sh = 0x400213
bourrage = 40

# Programme 32 bits mais kernel 64 bits
frame = SigreturnFrame(kernel="amd64")      
frame.eax = int(constants.SYS_execve)       # 0xb
frame.ebx = addr_bin_sh                     # parametre n°1
frame.ecx = 0                               # parametre n°2
frame.edx = 0                               # parametre n°3
frame.eip = int_0x80

payload = b'A' * bourrage
#payload += ...            # Mettre `constants.SYS_rt_sigreturn` dans `eax`
payload += p32(int_0x80)   # Appel systeme `sigreturn`
payload += bytes(frame)    # Structure `rt_sigframe`

"""
io.send(payload)
(...)
"""
```

Finalement, une fois le principe assimilé, passer du 32 bits au 64 bits ne présente pas de difficulté majeure.

## JOP (ou Jump-Oriented Programming)

Le **JOP** est une technique d'exploitation qui [a été proposée](https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf) afin d'éviter d'avoir à **dépendre de la pile** et **contourner d’éventuelles protections** ciblant le ROP qui pourraient être introduites ultérieurement.

Cette technique est toujours basée sur de la réutilisation de bouts de code présent en mémoire, protection **NX** oblige. Toutefois, cette réutilisation de code ne va pas se faire de la même manière.

Par exemple, les **maillons de la chaîne de JOP** n'ont **pas nécessairement besoin** d'être présents sur la **pile**. Ils peuvent être placés **autre part** en mémoire comme les sections `.bss`/`.data` ou même le tas.

### Fonctionnement global

Le processus global du **JOP** peut être résumé ainsi :

![](/assets/images/introduction_au_pwn/jop_schema.png)

Ce schéma tiré [du papier](https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf) qui décrit le fonctionnement du **JOP** synthétise les différentes parties dont on a besoin pour faire du **JOP**.

#### Le gadget dispatcher

Tout d'abord, il y a ce que l'on appelle le **gadget dispatcher**. Il s'agit d'un gadget, une succession d'instructions donc, qui permet de simuler le fonctionnement d'un **pointeur d'instruction** mais de manière **globale**. Comme son nom l'indique, son rôle est de dispatcher le flux d'exécution vers les différents gadgets placés dans la *dispatch table*.

Il peut avoir différentes formes en fonction du registre ou de la zone mémoire qui jouera le rôle de pointeur d'instruction. Par exemple, le gadget suivant accomplit cette tâche via le registre `rbx` :

```nasm
add rbx, 8
jmp [rbx]
```

Où `rbx` pointe à chaque instant vers l'une des entrées de la *dispatch table*.

L'outil `xgadet` possède l'option `-d`/`--dispatcher` permettant de trouver de potentiels **gadget dispatcher**.

#### La dispatch table

C'est la zone mémoire qui va contenir les **adresses des différents gadgets** à exécuter en vue d'atteindre un certain objectif (appeler une fonction de la **libc**, un appel système ...). C'est ici que seront placés les différents éléments de la chaîne de JOP.

En fonction de ce que fait tel ou tel gadget, il sera peut-être nécessaire **d'intercaler des données** entre les adresses de gadgets. Auquel cas, il faudra aussi faire en sorte que le **gadget dispatcher** ne tente pas d'exécuter une zone mémoire qui contient des données au lieu d'une adresse de gadget. 

> Mais va falloir plusieurs **gadget dispatcher** si on insère aussi des données dans la chaîne de **JOP** ? 
{: .prompt-info }

Oui, s'il y a des données, il faudra peut-être trouver des instructions qui feront incrémenter de 16, 24 ou 32 octets le registre pointant vers la **dispatch table**.

Sinon, il est possible de faire en sorte que :
- les données soient stockées à un endroit différent de la **dispatch table** ;
- les gadgets qui nécessitent des données fassent avancer eux-mêmes le pointeur de **dispatch table**.

#### Les gadgets

Les gadgets propres au **JOP** se terminent la plupart du temps par un **saut indirect** tel que `jmp rax`, ` jmp [rdx]` ... Pour autant, nous pouvons également envisager d'utiliser des instructions qui se terminent par un **appel indirect** tel que `call rax` ou `call qword ptr [r13 + 0x10]`.

Comme le **JOP** n'est, normalement, pas destiné à dépendre de la pile, nous ne pourrons pas utiliser de gadget du type `pop rxx`. Sauf si l'on réalise un **pivot de pile** auquel cas autant finir avec du bon vieux **ROP** 🙃.

Ainsi, il va falloir se débrouiller pour trouver des gadgets de **JOP** permettant de lire des données, en écrire, charger des registres etc. C'est sans doute la partie la plus pénible où il va falloir prendre le temps de trouver de tels gadgets.

Par ailleurs, il ne faut pas oublier un point important ⚠️ : tous les gadgets de la chaîne de JOP doivent **retourner, une fois leur exécution terminée, dans le gadget dispatcher** afin que ce dernier exécute le prochain gadget.

Si un gadget ne remplit pas cette condition :

- soit on le met de côté ;
- soit il doit faire en sorte d'exécuter lui-même le prochain gadget de la chaîne.

Je vous l'accorde, sur le papier ça a l'air d'être une technique d'exploitation révolutionnaire. Mais en pratique, c'est **très compliqué** à mettre en place et, comme vous pouvez le voir, elle nécessite pas mal de bidouillage et de nombreuses contraintes à respecter 😮‍💨.

### Exercice

Si vous souhaitez vous ~~faire mal à la tête~~ entraîner à faire du **JOP**, le challenge suivant devrait être ce qu'il vous faut : [juujuu](https://c4ebt.github.io/content/pwnday01/juujuu). Il possède même une [solution de résolution](https://c4ebt.github.io/2020/05/26/PWNDAY-01-Juujuu-Writeup.html) (en anglais).

> Je n'ai pas testé ce challenge donc je n'ai malheureusement pas d'indice à vous donner 😅.
{: .prompt-tip }