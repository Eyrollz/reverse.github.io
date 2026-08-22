---
title: Partie 10 - Comprendre les mécanismes de protection du BO - les canaris
date: 2026-04-29 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Comprendre les mécanismes de protection du *stack buffer overflow* : les canaris 🐤

![](/assets/images/introduction_au_pwn/pwn_canaries.png)

> Les développeurs de Linux et de la **libc** ne se sont pas rendus compte de toutes les attaques possibles pour exploiter les **dépassements de mémoire sur la pile** ?
{: .prompt-tip }

Le domaine de la recherche de vulnérabilité est une éternelle course **du chat et de la souris** : pendant que certains élaborent **des attaques** de plus en plus sophistiquées, d'autres mettent en place **des protections** de plus en plus robustes.

C'est pourquoi, plus on avancera dans ce cours, plus les méthodes d'exploitation vont devenir de **plus en plus complexes**. Ne vous inquiétez pas : si vous retenez progressivement les différentes méthodes d’exploitation et le fonctionnement des protections, vous ne devriez pas avoir de souci pour progresser en *pwn*.

## Le principe

Les canaris (ou *stack cookies* / *stack canaries* 🇬🇧) sont une protection relativement simple à comprendre. Elle répond à la problématique suivante : **comment détecter qu'un dépassement de mémoire sur la pile a eu lieu** ?

> Vous vous demandez peut-être **l'origine du nom** "canari". Historiquement, les mineurs emmenaient des canaris dans les mines pour détecter les gaz toxiques. Les canaris sont très sensibles aux variations d'air respirable, et leur détresse ou mort précoce avertissait les mineurs d'un danger imminent.
> 
> De la même manière, les canaris dans un programme **signalent la présence** d'un dépassement de tampon.
{: .prompt-tip }

L'idée globale est d'insérer sur la pile, juste avant l'**adresse de retour** et les **registres sauvegardés**, une valeur connue à l'avance (par le programme) lorsque l'on exécute la fonction. En fin de fonction, on vérifie si : 

- cette valeur est toujours la même ➡️ il n'y a ***a priori*** pas eu de dépassement de mémoire ✅ ;
- cette valeur a été modifiée ➡️ il y a eu un *buffer overflow*, le programme est arrêté ❌.

L’**objectif** n’est pas d’empêcher le *buffer overflow*, mais de **détecter son exploitation avant** qu’elle ne puisse détourner le flux d’exécution.

Si cela paraît encore un peu flou, je vous propose de voir ensemble ce qui se passe sur la pile au fur et à mesure que l'on avance dans l'exécution de `main` d'un programme quelconque. Tout d'abord, en entrant dans le `main` la valeur en tête de pile est l'adresse de retour, jusque-là je ne vous apprends rien :

![](/assets/images/introduction_au_pwn/main_1.png)

Lorsque le prologue est exécuté, différents registres sont sauvegardés. Idem, rien de nouveau ici :

![](/assets/images/introduction_au_pwn/main_2.png)
Ensuite, le **canari**, qui n'est rien d'autre qu'une **valeur aléatoire de 32 bits** (ou 64 en `x86_64`), est généré et inséré en tête de pile :

![](/assets/images/introduction_au_pwn/main_3.png)

> L'octet de poids faible du canari est **toujours** `0x00`. Nous verrons ultérieurement la cause de sa présence.
{: .prompt-tip }

À partir de là, la fonction `main` poursuit son exécution en faisant totalement abstraction du canari jusqu'à arriver à la fin de son exécution, juste avant l'épilogue. Une **vérification du canari** a été ajoutée par le compilateur et là, **deux scénarios** sont possibles :

![](/assets/images/introduction_au_pwn/main_4.png)

1. un dépassement de mémoire tampon a eu lieu. Le canari a été écrasé et sa valeur a donc été modifiée. Cela sera détecté et le programme sera arrêté avec un message du type `*** stack smashing detected ***: terminated`. ❌ ;
2. tout s'est bien passé et le canari a gardé sa valeur de départ ✅ ;

> Si la valeur du canari est modifiée, comment le programme peut s'en rendre compte vu qu'il ne l'a sauvegardée nulle part 🤨 ?
{: .prompt-info }

Très bonne question ! Voyons de plus près comment cela est concrètement implémenté afin de trouver une réponse à cette question.

## Les détails de l'implémentation

Le programme utilisé est toujours le même :

```cpp
#include "stdio.h"

int main()
{
  char prenom[256] = {0};
  gets(&prenom);
  printf("Bonjour %s !\n",prenom);
  return 0;
}
```

Pour le compiler : `clang -m32 -no-pie -fstack-protector  main.c -o canaris -Wno-implicit-function-declaration`.

L'accès au conteneur Docker de ce chapitre est le suivant :

- ⬇️ **Téléchargement** : [pwn-stack-canaris.zip](https://drive.proton.me/urls/KHRBQPVQ50#v5CPPuV92xxC)
- 🔎 **SHA256 & Analyse Virus Total** : [2822153a0d31eebf3b01e1d4b44aa4a635bed3c6639b4c01ef60d76a5a7ac231](https://www.virustotal.com/gui/file/2822153a0d31eebf3b01e1d4b44aa4a635bed3c6639b4c01ef60d76a5a7ac231)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-stack-canaris .
docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-stack-canaris
```

Nous voyons que la protection est bien présente via `checksec` :

```
$ pwn checksec canaris  
[*] '/opt/chal/canaris'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    Canary found         <-----
   NX:       NX enabled  
   PIE:      No PIE (0x8048000)
```

Vous l'avez deviné, c'est l'option `-fstack-protector` qui indique au compilateur d'utiliser les canaris. Jetons un œil au **code assembleur** du programme afin de comprendre comment se passe l'**insertion** et la **vérification** du canari :

![](/assets/images/introduction_au_pwn/canari_asm.png)

1. la valeur du canari est récupérée dans `eax` à partir de l'*offset* `0x14` du registre `gs`. Nous verrons ce à quoi correspond ce registre. Le contenu de `eax` est mis sur la pile (via `ebp`) ;
2. avant de quitter la fonction, la valeur du canari est récupérée dans `eax` depuis `gs` (**valeur initiale**) ainsi que dans `ecx` (**valeur potentiellement modifiée**). Ces deux registres sont ensuite comparés via `cmp` (parfois cela est fait via un `xor` dont le résultat doit être nul) ;
3. **deux cas** sont envisagés :
	- le canari n'**a pas été modifié** : on entre dans le bloc 🟢 et le programme termine normalement ;
	- le canari **a été modifié** : on entre dans le bloc 🔴 et le programme termine prématurément via un appel à `__stack_chk_fail`.

### 🐥 Où es-tu caché ?

> Nous allons **détailler davantage** l'implémentation du canari en mémoire. Cela implique des notions (et du vocabulaire) qu’il n’est pas nécessaire d’assimiler pour comprendre comment fonctionne un canari. Si vous avez du mal avec cette partie, passez à la suivante tant que vous avez retenu ce qui a été dit précédemment sur le fonctionnement du canari.
> 
> Pour les plus curieux et plus à l'aise avec le *pwn*, cette partie est tout de même intéressante car elle **ouvre des perspectives** d'exploitation permettant de modifier la valeur initiale du canari en mémoire 🫣.
{: .prompt-tip }

La question que vous vous posez sans doute : où est exactement stocké le canari ? Plus précisément : vers quoi pointe le registre de segment `gs` ?

Si vous tentez d'afficher la valeur de `$gs` dans **gdb** vous risquez de tomber sur une valeur du type `0x63` qui est un index dans la [GDT](https://fr.wikipedia.org/wiki/Global_Descriptor_Table) (**G**lobal **D**escriptor **T**able ).

> En réalité, un registre de segment peut pointer dans la **GDT** ou la [LDT](https://en.wikipedia.org/wiki/Global_Descriptor_Table#Local_Descriptor_Table) (**L**ocal **D**escriptor **T**able). 
> 
> Lorsque le **bit n°2** du registre est **nul**, c'est **GDT** qui est utilisée, **sinon**, c'est la **LDT**. En l'occurrence, comme la valeur de `gs` est `0x63`, c'est **GDT** qui est utilisée.
{: .prompt-tip }

Concrètement, cela permet, à partir d'un index, de récupérer une adresse. En l'occurrence, il s'agit d'une adresse vers une structure [pthread](https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/nptl/descr.h#L130) qui est dans le [TLS](https://fr.wikipedia.org/wiki/Thread_Local_Storage) (**T**hread **L**ocal **S**torage) : une zone mémoire permettant de gérer les *threads* d'un programme ainsi que les variables "thread-safe". C'est, entre autres, ce mécanisme qui permet à chaque **fil d'exécution** d'avoir ses **propres variables**. 

Pour revenir aux canaris, cela implique que **chaque fil d'exécution a son propre canari**.

Le premier membre de la structure `pthread` est une structure [tcbhead_t](https://elixir.bootlin.com/glibc/glibc-2.40/source/sysdeps/x86_64/nptl/tls.h#L42) qui est l'en-tête du [TCB](https://en.wikipedia.org/wiki/Thread_control_block) (**T**hread **C**ontrol **B**lock). Oui je sais, ça fait pas mal d'acronymes, n'hésitez pas à prendre le temps de les comprendre 😅. Grosso modo, le **TCB** est une structure contenue dans le **TLS**.

Voyons de plus près les différents membres de `tcbhead_t` :

```cpp
typedef struct
{
  void *tcb;		/* Pointer to the TCB.    */
  dtv_t *dtv;
  void *self;		/* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard; // 🐥
  uintptr_t pointer_guard;
  unsigned long int unused_vgetcpu_cache[2];

  unsigned int feature_1;
  int __glibc_unused1;
  void *__private_tm[4];
  void *__private_ss;
  unsigned long long int ssp_base;
  __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));

  void *__padding[8];
} tcbhead_t;
```

Le 7ème membre est nommé `stack_guard`. Sachant que chacun des 7 premiers membres est sur 4 octets (car nous sommes en 32 bits), l'offset de `stack_guard` est `0x14`, on retombe bien sur ce que l'on a vu plus haut avec `mov eax, gs:14h` !

Ainsi, `stack_guard` est bien le membre où est stocké le canari 🐥 !

> Ici `uintptr_t` pour `uintptr_t stack_guard;` ne signifie pas que ce membre contient un pointeur : il contient directement la valeur du canari.
{: .prompt-warning }

Voici un schéma qui résume ce qui se passe lorsque l'on souhaite **récupérer la valeur** qui est  **pointée par** `gs:0x14` :

![](/assets/images/introduction_au_pwn/gdt_gs.png)

C'est bien beau tout ça, mais ça c'était la théorie, maintenant comment trouver où est l'en-tête `tcbhead_t` ?

Dans **gdb** il est possible d'utiliser cette commande pour avoir quelques informations sur les *threads* du processus courant:

```
pwndbg> info threads        
 Id   Target Id                                Frame    
* 1    Thread 0xf7fbf500 (LWP 412671) "canaris" 0x080491c2 in main ()
```

Utilisons ensuite l'adresse retournée avec la commande suivante :

```
pwndbg> p/x *(tcbhead_t *) 0xf7fbf500  
$4 = {  
 tcb = 0xf7fbf500,  
 dtv = 0xf7fbfa88,  
 self = 0xf7fbf500,  
 multiple_threads = 0x0,  
 sysinfo = 0xf7fc4570,  
 stack_guard = 0x4210ea00,  <------- 🐥
 pointer_guard = 0x91b5254,  
 gscope_flag = 0x0,  
 feature_1 = 0x0,  
 __private_tm = {0x0, 0x0, 0x0},  
 __private_ss = 0x0,  
 ssp_base = 0x0  
}
```

Plus rapide : nous pouvons tout simplement utiliser la commande `tls -a` :

```
pwndbg> tls -a
Thread Local Storage (TLS) base: 0xf7fbf500
TLS is located at:
0xf7fbe000 0xf7fc0000 rw-p     2000       0 [anon_f7fbe]
Dumping the address:
tcbhead_t @ 0xf7fbf500
    0x00000000f7fbf500 +0x0000 tcb                  : 0xf7fbf500
    0x00000000f7fbf500 +0x0004 dtv                  : 0xf7fbfa88
    0x00000000f7fbf500 +0x0008 self                 : 0xf7fbf500
    0x00000000f7fbf500 +0x000c multiple_threads     : 0x0
    0x00000000f7fbf500 +0x0010 sysinfo              : 0xf7fc4570
    0x00000000f7fbf500 +0x0014 stack_guard          : 0x4210ea00
    0x00000000f7fbf500 +0x0018 pointer_guard        : 0x91b5254
    0x00000000f7fbf500 +0x001c gscope_flag          : 0x0
    0x00000000f7fbf500 +0x0020 feature_1            : 0x0
    0x00000000f7fbf500 +0x0024 __private_tm         : {0x0, 0x0, 0x0}
    0x00000000f7fbf500 +0x0030 __private_ss         : 0x0
    0x00000000f7fbf500 +0x0034 ssp_base             : 0x0
```

> Il peut être nécessaire d'installer `libc6-dbg:i386` et `libc6-dbg` pour que la commande `tls` fonctionne correctement.
{: .prompt-tip }

Nous avons réussi à **trouver la valeur du canari** en mémoire ! D'ailleurs, à partir de l'adresse de `tcbhead_t` nous savons désormais à peu près où est stocké le **TLS** :

![](/assets/images/introduction_au_pwn/tls_area.png)

> En fonction de la version de la **libc**, il est possible que cette zone mémoire soit *mappée* **avant** la zone mémoire utilisée par la **libc**.
{: .prompt-tip }

> Pour les programmes **x86_64**, le **même principe est utilisé** sauf qu'au lieu d'utiliser `gs:0x14`, c'est `fs:0x28` qui est utilisé. 
{: .prompt-tip }

On en déduit également **un point important** : si la vérification du canari est implémentée dans plusieurs fonctions, cela n'implique pas d'avoir **un canari par fonction**. Ces fonctions utiliseront **le même canari**, celui qui est dans le **TLS**. 

#### ✏️ Changer la valeur du canari

Nous ne sommes pas allés aussi loin dans les détails pour rien 😏. Vous remarquerez que la zone mémoire contenant la structure `tcbhead_t` dispose évidemment du **droit de lecture** `r`, mais également du **droit d'écriture** `w` !

Ainsi, si nous disposons d'une **primitive d'écriture arbitraire**, il est en théorie possible de réécrire la valeur du canari avec **une valeur arbitraire** que nous pourrons réutiliser dans notre *payload* afin d'éviter que le programme détecte un *buffer overflow*.

En pratique, le **TCB** est situé à une adresse soit **fixe** ou **presque fixe**, par rapport à la **libc**, qu'il est possible de trouver par **force brute** si besoin.

## 📋 Synthèse

Le principe des canaris est simple : une **valeur aléatoire** est insérée sur la pile, juste avant l'adresse de retour. À la fin de l'exécution de la fonction, cette valeur est vérifiée :

- **si inchangée** : pas d'anomalie détectée, le programme continue ✅ ;
- **si modifiée** : un dépassement de tampon est suspecté, et le programme est arrêté immédiatement ❌.

La **valeur initiale** du canari est stockée en mémoire dans le **TCB** qui contient des informations du **fil d'exécution** courant. Il est possible de modifier cette valeur sous certaines conditions.