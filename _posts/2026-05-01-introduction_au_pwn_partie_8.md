---
title: Partie 8 - Exploiter un BO - attaque ret2libc – concepts et prérequis (1/2)
date: 2026-05-01 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter un *stack buffer overflow* : attaque *ret2libc* – concepts et prérequis (1/2)


![](/assets/images/introduction_au_pwn/pwn_t_3.png)

Poursuivons notre aventure dans le temps ⏳. Nous allons encore une fois nous intéresser à une méthode d'exploitation qui a lieu dans la pile : **ret2libc** (ou retour à la **libc** 🇫🇷).

En quoi consiste **ret2libc** ? Nous allons le découvrir dans quelques instants.

## Contexte

Nous allons nous placer dans le même contexte que lors de l'exploitation via la pile exécutable avec quelques différences :

- nous considérons que l'**ASLR** est toujours **désactivée** (comme ce fut le cas précédemment) ;
- la pile n'est **plus** exécutable ;
- **aucune** autre **protection** n'est déployée.

Pour le code à exploiter, on reprend notre bon vieux programme :

```cpp
#include "stdio.h"  

int main()  
{  
 char prenom[256] = {0};  // /!\ augmentation de la taille
 gets(&prenom);  
 printf("Bonjour %s !\n",prenom);  
 return 0;  
}
```

Pour le compiler en 32 bits sans que la pile ne soit exécutable : `clang -m32 -no-pie -fno-stack-protector main.c -o ret2libc -Wno-implicit-function-declaration`.

> L'option `-Wno-implicit-function-declaration` évite d'avoir une erreur de compilation liée à la présence de la fonction `gets`.
{: .prompt-tip }

Pour suivre le cours via un conteneur Docker dédié :

- ⬇️ **Téléchargement** : [pwn-stack-ret2libc.zip](https://drive.proton.me/urls/C5JW29KC7R#imq51JLFQ4Bn)
- 🔎 **SHA256 & Analyse Virus Total** : [87b281aa28d0845c71a61f0345ba09ef3e0dcdcb496c25030472fd24b5ff0496](https://www.virustotal.com/gui/file/87b281aa28d0845c71a61f0345ba09ef3e0dcdcb496c25030472fd24b5ff0496)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-stack-ret2libc .
docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-stack-ret2libc
```

> Pourquoi, d'un coup, on se met à compiler avec **clang** ?
{: .prompt-info }

La compilation avec **clang** va permettre d'avoir, dans `main`, un **épilogue plus simple** à gérer que ce que l'on a pu voir précédemment. Vu que vous savez désormais comment gérer ça, autant éviter de se mettre des bâtons dans les roues 😇. Également, nous compilons en **32 bits** car l'exploitation via **ret2libc** est bien plus simple en 32 bits.

![](/assets/images/introduction_au_pwn/gcc_vs_clang.png)

Bon, comment exploiter ce programme maintenant que la pile est désormais **non exécutable** ?

## Exploitation

> Pour rappel, on se place dans un contexte où **l'ASLR est désactivée** via la commande suivante : `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`.
> 
> ⚠️ A ne pas faire dans son environnement de travail de tous les jours.
{: .prompt-tip }

Tout d'abord parlons de `checksec`, un des **modules de** `pwntools`. `checksec` donne un aperçu des principales protections présentes dans un programme. Vous pouvez l'utiliser en ligne de commande avec `pwn checksec nom_du_programme` ou tout simplement `checksec nom_du_programme`.

> `pwntools` est déjà installé dans le conteneur Docker. Si vous souhaitez l'installer sur votre machine, il y a une section dédiée à cela un peu plus bas 😉.
{: .prompt-tip }

Pour ce programme, cela donne :

```
$ pwn checksec ret2libc  
[*] '/home/(...)/ret2libc'  
   Arch:     i386-32-little  
   RELRO:    Partial RELRO  
   Stack:    No canary found  
   NX:       NX enabled         <----
   PIE:      No PIE (0x8048000)
```

> Il y a sûrement certaines protections que vous ne comprenez pas pour l'instant, nous aurons l'occasion de nous y attarder plus tard.
{: .prompt-tip }

C'est à travers la ligne `NX:  NX enabled` que nous comprenons que la pile **n'est pas exécutable**.

> N'hésitez pas à utiliser `checksec` lorsque vous faites face à un challenge de *pwn*. Ça ne mange pas de khobz et cela donne **une idée des protections** qu'il va peut-être falloir déjouer.
{: .prompt-tip }

### Contrôler `eip`

La première étape est de contrôler `eip` et vous savez comment faire depuis le temps. On constate, en tâtonnant, qu'en utilisant un bourrage de **268** `'A'` que les **4 prochains octets** permettent de **contrôler** `eip` :

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0123
```

Le résultat dans **gdb** : 

![](/assets/images/introduction_au_pwn/eip_ctlred.png)

Première étape terminée *illico presto* 😎.

La question que tout le monde se pose désormais : on fait quoi maintenant ? La pile n'est plus exécutable 😞, nous ne pouvons donc plus utiliser un *shellcode* pour ouvrir un terminal. Essayons de voir ce que nous pouvons faire.

Nous contrôlons déjà `eip`, ce qui signifie que nous pouvons **sauter vers n'importe quelle adresse** exécutable de notre programme. Pas de bol, notre code ne fait pas grand-chose. Les fonctions qu'il appelle ne nous permettent pas d'avancer bien loin.

C'est **là** que la technique **ret2libc** entre en jeu !

### ret2libc

![](/assets/images/introduction_au_pwn/9bxi3h.gif)

**ret2libc** consiste à sauter dans la **libc** afin d'être en mesure d'exécuter des fonctions intéressantes nous permettant, *in fine*, d'avoir un *shell*. 

Sachant que `execve` est une **fonction** à part entière de la **libc**, autant l'exécuter plutôt que de passer du temps à rendre une zone mémoire exécutable pour y mettre un *shellcode* qui lui-même exécutera l'appel système `execve` 😴. 

> **Rappel** : Ce que nous souhaitons exécuter, via la **libc**, est la **fonction** `execve`, pas **l'appel système** éponyme (même si la fonction `execve` finit par exécuter cet appel système).
{: .prompt-tip }

> Comment se fait-il que des fonctions que l'on n'appelle pas depuis notre programme se retrouvent dans la mémoire de notre processus ?
{: .prompt-info }

Il suffit d’utiliser **une seule** fonction de la **libc** pour que celle-ci soit **totalement chargée** dynamiquement lorsque notre programme est lancé. Rappelez-vous, la **libc** est un fichier ELF, il serait difficile d'en extraire **seulement** les fonctions et instructions utiles pour notre programme.

Tant pis pour la mémoire supplémentaire utilisée pour stocker des fonctions qui ne seront jamais appelées. Sandrine Rousseau a sûrement de plus grandes batailles à mener ! De notre côté, tant mieux pour nous car cela nous donne accès à beaucoup de fonctions intéressantes telles que `execve`.

D'ailleurs, rien ne nous interdit d'appeler une autre fonction que `execve` afin d'ouvrir un *shell*. Nous pourrions très bien utiliser `system`, `execv`, `execl` ... Voici les signatures de ces fonctions :

```cpp
int system(const char *command);
int execv(const char *pathname, char *const argv[]);
int execve(const char *pathname, char *const argv[], char *const envp[]);
int execl(const char *pathname, const char *arg, ... /* (char  *) NULL */);
```

> En *pwn*, il convient de ne pas se restreindre à la première piste d'exploitation envisagée. Si, effectivement, une piste semble **plus adaptée** que d'autres, ce n'est pas pour autant qu'il faut la considérer comme étant **l'unique** méthode permettant d'exploiter le programme.
> 
> Il arrive parfois, en suivant une piste qui semble être "la bonne", de faire face à des **obstacles** qui n'auraient pas existé si **une autre piste** avait été choisie.
{: .prompt-tip }

En l'occurrence chacune de ces fonctions dispose d'**avantages** et d'**inconvénients** :

- `system` : 
	- elle a l'**avantage** de ne prendre d'un **seul argument** mais les privilèges SUID sont toujours **abandonnés** lors de l'appel de cette fonction qui est totalement équivalente à `execl("/bin/sh", "sh", "-c", commande, (char *) NULL);`
	- un autre **avantage** est qu'il n'est pas obligatoire d'utiliser un chemin absolu pour la commande. Il est donc tout à fait possible d'utiliser `"bash"` ou `"ma_cmd"` tant que la commande `ma_cmd` est trouvable dans l'un des dossiers listés dans la variable d'environnement `PATH` ;
	- cette fonction sera **à privilégier** dans le cadre de challenges à distance où il n'y a pas besoin de réaliser une élévation de privilèges ou bien dans des challenges où `setreuid` a déjà été appelé.
- `execv` : 
	- cette variante ne prend que 2 arguments, ce qui est plus facile à gérer que `execve` mais plus compliqué que `system` qui ne prend qu'un argument ;
	- il est possible d'appeler `/bin/sh -p`, `/usr/bin/python3` ou un *wrapper* appelant `setreuid` afin de ne pas perdre les privilèges lors de l'ouverture du terminal.
- `execl` :
	- cette fonction dispose peu ou prou des mêmes avantages et inconvénients que `execv` ;
	- la différence est qu'il s'agit d'une [fonction variadique](https://fr.wikipedia.org/wiki/Fonction_variadique) (comme `printf`). Il est donc possible de spécifier les paramètres sous forme de plusieurs arguments au lieu de fournir un tableau d'arguments comme c'est le cas dans `execv`.
- `execve` :
	- quasiment identique à `execv` si ce n'est que la fonction requiert de spécifier l'argument `envp` qui n'est pas toujours nécessaire ...

> En réalité il y a bien plus de variantes mais si vous avez compris les différences entre celles-ci, vous ne devriez pas avoir de mal à comprendre les autres. Vous pouvez voir ces différentes variantes avec `man execv`.
{: .prompt-tip }

> Le `l` dans `execl` est pour **list** (paramètres sous forme de **liste**) tandis que le `v` dans `execv` est pour **vector** (paramètres sous forme de **tableau**). Cela vous aidera à distinguer les deux.
{: .prompt-tip }

- nous n'avons pas de raison particulière de spécifier les variables d'environnement, nous pouvons donc mettre de côté `execve`. 
- notre programme n'appelle pas `setreuid` et il ne s'agit pas d'un challenge à distance, de ce fait `system` ne nous permettra pas de devenir `root` en l'état.

Il nous reste à choisir parmi `execv` et `execl`. Comme nous avons déjà utilisé `execve` dans le précédent chapitre et que cette fonction s'utilise comme `execv`, je vous propose d'utiliser `execl` afin de découvrir de nouvelles choses 😉.

Ce chapitre, en lui-même, ne sera pas très compliqué. Je vous suggère donc de vous introduire la bibliothèque Python [pwntools](https://github.com/Gallopsled/pwntools) !

## pwntools

![](/assets/images/introduction_au_pwn/pwntools_logo.png)

**pwntools** est une bibliothèque Python permettant de faciliter l'exploitation de binaires. Elle dispose notamment des fonctionnalités suivantes :

- **interaction avec le processus** : il est possible de lancer et interagir avec un programme à exploiter en local, à distance (via TCP ou UDP) ou même en se connectant en SSH si cela est possible ;
-  **manipulation de données** : la conversion de données, notamment d'octets en entier et inversement. Cela est très utile lorsque l'on souhaite convertir des adresses en octets pour les ajouter au *payload* ;
-  **assistance au développement d’exploits** : dans certaines techniques d'exploitation couramment utilisées (écriture de *shellcode*, ROP, chaîne de caractères formatées ...) il existe des modules qui vous facilitent l'exploitation de binaire via ces techniques ;
- **assemblage et désassemblage** : si vous aimez utiliser capstone et keystone pour assembler et désassembler, sachez qu'il est possible de le faire facilement avec **pwntools** ;
- **débogage à la volée** : il s'agit peut être de ma **fonctionnalité préférée** dans **pwntools**. Imaginez que vous êtes en train d'exploiter un challenge nécessitant une dizaine d'étapes. Vous avez réussi les 9 premières étapes et vous bloquez à la dernière. Vous n'arrivez pas à comprendre d'où vient le problème, vous utiliser donc un débogueur pour en savoir plus. Le souci est que si vous ouvrez **gdb**, vous aurez à relancer les 9 premières étapes pour arriver au point bloquant. En revanche, avec la fonction `gdb.attach()`, vous pouvez ouvrir à la volée, dans **gdb**, le processus exploité après avoir terminé les 9 premières étapes pour arriver directement au point bloquant et pouvoir en découvrir la cause. Pratique non 🤩 ? 
- **automatisation de l'envoi et réception de données** : un autre point fort de **pwntools** est la facilité à envoyer et recevoir des données, notamment un *payload* sous forme d'octets, au processus exploité.

La liste n'est pas exhaustive mais cela vous illustre à quel point **pwntools** est LA boîte à outils que toute personne qui se lance dans le **pwn** doit connaître. Si vous avez déjà jeté un œil à des solutions (*writeups* 🇬🇧), je suis sûr que vous avez déjà rencontré des scripts Python utilisant **pwntools**.

> Pour installer **pwntools**, il suffit d'exécuter les quelques commandes présentes sur [ce tutoriel](https://docs.pwntools.com/en/stable/install.html). 
{: .prompt-tip }

Reprenons ce que nous avons fait jusque-là (contrôler `eip`) mais en utilisant **pwntools** dans `script.py`. Tout d'abord, voici une version intermédiaire pour comprendre comment fonctionne **pwntools** :

```python
from pwn import *

io = process("./ret2libc")

io.sendline(b"azert")

print(io.recv())
```

Décortiquons ensemble ces quelques lignes :

- `from pwn import *` : on ne se casse pas la tête, on importe tous les modules de **pwntools** ;
- `io = process("./ret2libc")` : nous **lançons le programme** `ret2libc`. A ce stade, `io` est la variable qui nous permettra d'interagir avec le processus en cours d'exécution afin d'envoyer et recevoir des données, l'arrêter etc. ;
- `io.sendline(b"azert")` : comme le programme utilise la fonction `gets` afin de récupérer l'entrée utilisateur, nous devons toujours ajouter un saut de ligne à la fin des données envoyées. C'est ce que fait la fonction `sendline()` (contrairement à `send()`) qui ajoute automatiquement un **saut de ligne** aux **données envoyées**. Vous remarquerez que les données à envoyer sont des octets (de type Python `bytes`) même si le programme s'attend à une chaîne de caractères. Si vous envoyez directement une chaîne de caractères, vous aurez un avertissement et cette dernière sera encodée en ASCII si possible. 
	- ℹ️ Les fonctions du type `send...()` permettent **d'envoyer des données** au processus dans `stdin` ✏️.
- `print(io.recv())` : cette ligne permet d'afficher le contenu de `stdout`. C'est là qu'écrivent des fonctions comme `printf` et `puts`. 
	- ℹ️ Les fonctions du type `recv...()` permettent de **recevoir des données** depuis le processus dans `stdout` 📄.

En lançant le script avec `python3 script.py`, voici un exemple de sortie que nous pouvons avoir :

```
[+] Starting local process './ret2libc': pid 134386  
[*] Process './ret2libc' stopped with exit code 0 (pid 134386)  
b'Bonjour azert !\n'
```

> Pour ceux qui ne connaissent pas encore [IPython](https://ipython.org/), je vous recommande de l'utiliser sans modération avec **pwntools**. Cela peut aider à trouver rapidement une fonction à envoyer ou à tester un *input* avant de l'intégrer dans le script.
> 
> Nous avons brièvement parlé de **IPython** dans le cours d'introduction à **angr** si vous souhaitez [y jeter un œil](https://reverse.zip/posts/introduction_a_l_execution_symbolique_avec_angr_partie_2/#ipython). 
{: .prompt-tip }

Maintenant que nous comprenons à quoi servent ces lignes, voici une version améliorée du script permettant d'écraser l'adresse de retour avec `0xdeadbeef` :

```python
from pwn import *

io = process("./ret2libc")

payload = b"A" * 268 # plus pratique non ;) ?
payload += p32(0xdeadbeef)

io.sendline(payload)

io.interactive()
```

> **Astuce pwntools** : La fonction `p32` permet de convertir un entier de 32 bits en octets. Par défaut, le format *little endian* est utilisé. Pour changer, vous pouvez spécifier au début de votre script `context.endian = 'big'`.
{: .prompt-tip }

> **Astuce pwntools** : `io.interactive()` ouvre un terminal interactif pour communiquer (recevoir l'*output* et envoyer un *input*) au processus. Cela évite d'avoir à appeler `io.send()` et `io.read()` à chaque fois.
{: .prompt-tip }

En lançant le script, on obtient la sortie suivante :

```
[+] Starting local process './ret2libc': pid 139513  
[*] Switching to interactive mode  
Bonjour AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ\xde !  
[*] Got EOF while reading in interactive  
$    
[*] Process './ret2libc' stopped with exit code -11 (SIGSEGV) (pid 139513)
```

Tout s'est passé comme prévu, le programme a planté avec un `SIGSEGV`. Et si on voyait ensemble ce que ça donne dans **gdb** histoire de rentrer dans le vif du sujet ? Voici comment faire en utilisant `gdb.attach()` :

```python
from pwn import *

io = process("./ret2libc")

payload = b"A" * 268
payload += p32(0xdeadbeef)

gdb.attach(io, '''
b *0x804921f
continue
''')

io.sendline(payload)

io.interactive()
```

> Si vous utilisez le script dans un environnement où il n'est **pas possible d'ouvrir de nouvelle fenêtre** (connexion SSH, conteneur Docker ...), vous aurez sûrement une erreur du type `Could not find a terminal binary to use. Set context.terminal to your terminal.`
> 
> Vous pouvez **installer** `tmux`  (installé par défaut dans les conteneurs Docker du cours) pour que vous puissiez tout de même avoir accès à **gdb** dans la même fenêtre de terminal.
{: .prompt-tip }

> Si vous avez une erreur du type `ptrace: Operation not permitted.` dans **gdb**, vous pouvez ajouter l'option `--user root` dans la commande `docker run (...)`.
> 
> Très souvent le programme est à exploiter avec un **utilisateur non privilégié** (tel que `challenger`). Ainsi, **n'oubliez pas de supprimer** cette option une fois que vous souhaitez exploiter le programme dans le contexte attendu.
{: .prompt-tip }

Quelques remarques concernant ce script :

- l'appel à `gdb.attach()` est réalisé **après** le lancement du processus mais **avant** d'envoyer la charge utile au processus. Il s'agit donc du moment où le processus attend l'entrée utilisateur ;
- nous mettons un point d'arrêt à `0x804921f` qui est l'adresse du `ret` de la fonction `main` ;
- utiliser `continue` ici permet de poursuivre l'exécution du programme et faire abstraction du point d'arrêt que **gdb** a mis par défaut en s'attachant au processus en cours d'exécution.

Vous l'avez deviné, lorsque `io.sendline(payload)` sera exécutée, le processus arrivera à la fin du `main` et **gdb** arrêtera l'exécution à ce stade ce qui nous donnera l’occasion de voir comment mettre en place le **ret2libc**.

> **Astuce pwntools** : Lorsque vous utilisez `gdb.attach()`, pensez à laisser, à la fin du script, une ligne du type `io.interactive()` ou `IPython.embed()` afin de garder le processus en vie. Le cas échéant, la fenêtre de **gdb** se fermera aussi vite qu'elle s'est ouverte.
{: .prompt-tip }

> **Astuce pwntools** : Vous pouvez changer la version de **gdb** que **pwntools** utilise en créant un lien symbolique `/usr/bin/pwntools-gdb`. 
> 
> Par exemple : `sudo ln -s /usr/bin/gdb-gef++ /usr/bin/pwntools-gdb`
{: .prompt-tip }

En lançant le script, une fenêtre **gdb** s'est effectivement ouverte :

![](/assets/images/introduction_au_pwn/pop_gdb.png)

## 📋 Synthèse

Au cours de ce chapitre nous avons vu le principe de **ret2libc**.

- cette technique est utilisée lorsque la **pile n'est pas exécutable** et que **l'ASLR est désactivée** ;
- **ret2libc** consiste à appeler une fonction de la **libc** en modifiant l'adresse de retour et en saisissant les arguments nécessaires à cette fonction ;
- la **fonction à appeler** est généralement une fonction permettant **d'ouvrir un terminal** comme `execv`, `execl`, `system` etc. ;
- comme d'habitude, une étape intermédiaire très importante est de **contrôler** `eip`, en l'occurrence exploitant un dépassement de mémoire tampon sur la pile ;
- nous avons appris à lancer et communiquer avec un processus mais aussi comment le déboguer à la volée via **pwntools** qui est la bibliothèque Python la plus utilisée en **pwn**.

