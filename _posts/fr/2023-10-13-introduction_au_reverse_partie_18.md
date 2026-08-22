---
title: Partie 18 - Le user land et kernel land
date: 2023-10-13 10:00:00
categories: [Reverse, Introduction au reverse]
tags: [x86, reverse, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Le user land et kernel land

Vous vous êtes toujours demandé la différence entre le noyau de votre OS, un programme lambda et un pilote ?

Ça tombe bien ! Nous allons tenter de comprendre comment interagissent ces différents composant d'un système d'exploitation. L'idée est que vous puissiez avoir une vision globale de l'interaction entre le **user land** et **kernel land** sans pour autant entrer dans les détails du kernel land.

D'ailleurs, vous le saviez, vous, que le **kernel Linux** était un fichier **ELF** et que le **kernel Windows** était un fichier **PE** 😲 ?

> Sous linux, le kernel se trouve ici : `/boot/vmlinuz-$(uname -r)`. Vous pouvez suivre les [étapes indiquées ici](https://unix.stackexchange.com/a/610685) afin de constater par vous-même que le **kernel** n'est finalement qu'un fichier **ELF** 🙃.
{: .prompt-tip }

> Sous Windows, le kernel est normalement présent ici : `C:\Windows\System32\ntoskrnl.exe`.
{: .prompt-tip }

## Les appels système (ou syscalls)

Nous n'allons pas nous **attarder** sur le *kernel land* en termes de *reverse* car il est nécessaire d'être très à l'aise en rétro-ingénierie et d'avoir des connaissances avancées concernant le fonctionnement su *kernel land* et ce n'est pas forcément un chapitre qu'il convient d'entamer dans un cours d'introduction au *reverse*.

Néanmoins, il y a une fonctionnalité que vous risquez de rencontrer et qui est à la limite du *user land* et du *kernel land* : les **appels système** (ou **syscalls**).

Derrière ce nom alambiqué se cache une solution à une problématique relativement simple. 

### La problématique

Voici comment on pourrait représenter la mémoire du PC à un instant T (sous Linux mais sous Windows le principe et plus ou moins le même) :

![](/assets/images/introduction_au_reverse/kernel_user_hw.png)

Nous pouvons distinguer 3 parties :

- Le **user land** : c'est la partie visible de l'iceberg, celle à laquelle on est confrontés tous les jours : navigateur, terminal, programme compilé, serveur web et j'en passe.
- Le **hardware** : il s'agit du matériel et périphérique que l'on branche à un ordinateur, qui peuvent être essentiels (RAM, Disque dur / SSD ...) ou non (imprimante, carte graphique dédiée, souris, clavier, ethernet ...).
- Le **kernel land** : l'accès au matériel et périphériques étant beaucoup trop sensible ( exemple : risque de sabotage du Disque dur si mal utilisé), il n'est pas possible de laisser n'importe quel programme en *user land* y accéder. Il faut donc que des programmes bien spécifiques, appelés pilotes, modules ou *drivers* opèrent ce délicat travail . Le *kernel land* contient le ***kernel*** (noyau, merci Sherlock 🕵️‍♂️) de l'OS. Le noyau est chargé de faire un tas de choses dont : l'ordonnancement, la gestion de la mémoire physique et virtuelle ...

> Ok je comprends bien, donc les pilotes gèrent les accès au *hardware* afin que tout se passe bien, jusque-là, c'est ok.
> 
> Mais comment fait un programme en *user land*, par exemple mon navigateur, pour se connecter à internet s'il n'a pas directement accès à la carte réseau WiFi / Ethernet 🤔 ?
{: .prompt-info }

C'est justement **LA problématique** susmentionnée à laquelle les **appels système** vont nous permettre de répondre : comment interagir avec des composants ou fonctionnalité bas niveau à partir du *user land* ?

### Un appel système, comment ça marche ?

Premièrement voici une manière de représenter **l'utilité des appels système** dans le précédent schéma :

![](/assets/images/introduction_au_reverse/syscall_schema.png)

Les **appels systèmes** vont jouer le rôle d'**interface** entre le **user land** et le **kernel land**. 

Les **syscalls** sont des fonctions [prédéfinies](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md) présentes dans le *kernel* lui même. La liste des *syscalls* (sous Linux) est disponible dans le fichier [include/linux/syscalls.h](https://elixir.bootlin.com/linux/v5.14.14/source/include/linux/syscalls.h). 

Si on y jette un œil, au vu des noms de fonctions qui sont assez explicites, on constate qu'il y a des fonctions de gestion de fichiers (`sys_read`, `sys_write`, `sys_open`, `sys_close` ... ) de gestion de mémoire (`sys_mmap`, `sys_mprotect`, `sys_munmap` ...) et bien d'autres.

> Par abus de langage, on parle souvent de *syscall* `read` pour parler de `sys_read`, `write` pour `sys_write` etc.
{: .prompt-tip }

Vous remarquerez que beaucoup de ces noms de fonctions ressemblent tout simplement à des fonctions de la libc (`read`, `write`, `mmap` ...). D'ailleurs, les fonctions associées dans la libc ne sont "que" des **surcouches** (*wrappers*) aux appels système idoines.

Quoi ? Vous ne me croyez pas 😞 ? Alors voici un exemple avec la fonction `read` :

```cpp
#include <unistd.h>  
#include <stdio.h>  
  
int main()  
{  
 char buff[20];  
 read(0,buff,10);  
  
 return 1;  
}
```

Compilons-le en statique afin de pouvoir voir le contenu de `read` ... en analyse statique : `gcc -static main.c -o exe`.

Si vous ouvrez le programme dans IDA et allez dans `read`, vous verrez cela :

![](/assets/images/introduction_au_reverse/read_wrapper.png)

En assembleur, le *syscall* est réalisé avec l'instruction `syscall` (merci Sherlock 🕵️‍♂️) :

![](/assets/images/introduction_au_reverse/syscall_asm.png)

> En fait, l'instruction `syscall` n'est disponible qu'en **x86_64**. Ainsi, pour réaliser un appel système en **x86**, c'est plutôt l'instruction (plus précisément, interruption) `int 0x80` qui est utilisée.
{: .prompt-tip }

> Il y a une [convention d'appel](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#calling-conventions) à respecter lorsque l'on souhaite réaliser un appel système. Par exemple mettre le numéro du *syscall* dans `eax`/`rax`. Néanmoins, comme nous n'allons pas nous attaquer au *reverse kernel land*, il n'est pas nécessaire de nous y attarder.
{: .prompt-tip }

Convaincus maintenant 😏 ?

En somme, un appel système est une **fonction prédéfinie** du kernel que l'on peut appeler depuis le *user land*. Le **kernel se débrouille** ensuite pour utiliser les bons modules/pilotes afin de satisfaire la demande (lecture de l'entrée standard, allocation de mémoire, écriture dans un fichier ...).

Si vous souhaitez comprendre davantage le fonctionnement des appels système, [cet article](https://blog.slowerzs.net/posts/linux-kernel-syscalls/) est fait pour vous. Il est rédigé en anglais mais permet de comprendre les aspects techniques sous-jacents lors d'un *syscall*.

> Dans le précédent schéma, tous les *syscall* finissent dans le *kernel*. N'est-il pas possible d’interagir aussi avec les différents pilotes en *kernel land* ?
{: .prompt-info }

Il est effectivement possible d'interagir avec des *drivers* avec un **appel système** bien précis sous Linux : `ioctl` (et `DeviceIoControl` sous Windows). 

L'explication et le fonctionnement de ce *syscall* sortent du cadre de ce cours et puis, de toute manière, on ne le voit pas très souvent quand on débute en *reverse*, sauf éventuellement dans des programmes qui nécessitent d'échanger des données avec certains pilotes. Cela peut être le cas, par exemple, des programmes système. 

> Si vous êtes également intéressés au sujet de la gestion des **interruptions**, voici un petit résumé qui en parle : [les interruptions](https://fr.wikibooks.org/wiki/Programmation_Assembleur/x86/Les_interruptions).
{: .prompt-tip }

