---
title: Partie 30 - Annexe - mise en place et résolution des challenges
date: 2026-04-09 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# Annexe : mise en place et résolution des challenges

Certains challenges et exercices seront donnés sous forme d'une **archive** contenant très souvent un **Dockerfile** ainsi que le **programme à exploiter**. D'autres éléments peuvent aussi être présents.

Utiliser la conteneurisation via Docker permet de s'assurer au mieux que vous puissiez résoudre les challenges indépendamment de votre distribution. Encore une fois, le mieux est que vous disposiez d'une machine ou VM sous **Ubuntu 24.04** si cela est possible. De cette manière cela **limitera les potentiels soucis de compatibilité**.

## 📁 Que contient l'archive du challenge ?

Tout d'abord, un l**ien de téléchargement** vers l'archive contenant le challenge sera présent sur la page du challenge. Une fois téléchargé, vous pourrez y trouver ces éléments :

| Fichier       | Utilité                                                                                                                                                                                | Présence      |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| 🐳 Dockerfile | Fichier de configuration du conteneur Docker                                                                                                                                           | Obligatoire ✅ |
| ⌨️ Programme  | C'est le challenge, à savoir : un **fichier binaire à exploiter**.                                                                                                                     | Obligatoire ✅ |
| 📄 flag.txt   | Fichier dont le **contenu est à afficher** lorsqu'il s'agit de l'objectif du challenge                                                                                                 | Facultatif ✔️ |
| 📚 libc et ld | Lorsque le challenge doit être résolu avec une version spécifique de la libc, la **libc** et **ld** (éditeur de liens) seront fournis (mais leur présence peut également être anodine) | Facultatif ✔️ |

> Une autre idée pour avoir facilement accès aux challenges aurait été de mettre les conteneurs en ligne sur **Docker Hub**. Le souci est qu'il est nécessaire d'avoir une connexion internet pour pouvoir rapidement *pull* l'image. De plus, vous ne pourrez pas avoir facilement accès aux fichiers tels que le Dockerfile ou le programme pour les manipuler/modifier.
> 
> En tout cas, si vous avez une **meilleure solution** que de mettre des archives zippées, nous sommes preneurs 🤓.
{: .prompt-tip }

## 🎯 Quel est l'objectif du challenge ?

L'**objectif** sera toujours **précisé dans l'énoncé** du challenge. Cela peut être :

- réussir à exécuter une fonction en particulier ;
- exécuter un *shellcode* qui fait telle ou telle chose ;
- ouvrir un terminal (*shell*) ;
- devenir `root` ;
- afficher le *flag* ...

Il se peut qu'il y ait de temps à autre des restrictions supplémentaires à appliquer telle que : "exploiter le programme **à distance** sans l'exécuter en local".

## 💫 Comment lancer le challenge ?

Les différentes commandes permettant de lancer le challenge seront **précisées sur la page de téléchargement** du challenge. Généralement cela se fait en 3 étapes :

1️⃣ **Construction de l'image docker**

C'est une commande qui ressemble à `docker build -t XXXXXXXX .`  où `XXXXXXXX` est le nom/tag de l'image.

> C'est normal que cette étape prenne 1000 ans 😩 ?
{: .prompt-info }

Cette étape peut prendre un certain temps (de l'ordre de **quelques minutes**) notamment pour l'installation des **différents outils**. Eh oui, quand on veut avoir tout à porter de main il faut savoir faire preuve de patience.

2️⃣ **Lancement du conteneur**

Le lancement du conteneur se fait avec une commande commençant par `docker run (...)`. Cette commande sera donnée sur la page du challenge car ses paramètres diffèrent d'un challenge à un autre.

3️⃣ **Lancement du challenge**

En fonction du type de challenge (résolution à distance ou locale) le lancement du challenge ne sera pas la même. C'est pourquoi la commande de lancement du challenge sera également spécifiée dans la page du challenge. Sinon, c'est par défaut `./nom_du_programme`.

## ⚙️ Comment déboguer le programme ?

Vous devriez toujours avoir accès au sein du conteneur docker à :

- **gdb** pour déboguer le programme **en local** ;
- **gdbserver** ainsi que l'ouverture du port `1234` afin de pouvoir déboguer **à distance** si besoin.

### Débogage en local

Il sera possible de déboguer localement le challenge en lançant **gdb** via un terminal dans le conteneur. Cela peut se faire avec `docker exec -it --user root XXXXXX /bin/bash` où `XXXXXX` est l'identifiant du conteneur obtenu avec `docker ps`.

Ensuite vous aurez accès à un terminal dans le conteneur et vous pourrez y lancer **gdb**.

> Nous avons choisi de ne pas inclure **toutes les différentes versions** de **gdb** pour plusieurs raisons. Tout d'abord le fait d'inclure une seule version augmente considérablement le temps de *build*. Deuxièmement, le fait d'inclure toutes les versions peut poser problème lors du *build*.
> Cela permet également d'éviter d'alourdir le conteneur.
> 
> De toute manière, une fois que le conteneur est lancé, vous pourrez y installer n'importe quel version / extension de **gdb** en y ouvrant un terminal.
{: .prompt-tip }

### Débogage à distance

Il existe plusieurs solutions pour déboguer à distance. L'une d'elles est d'ouvrir un terminal dans le conteneur :

```sh
docker exec -it --user root ID_CONTENEUR /bin/bash
```

Ensuite vous avez le choix :

Soit vous souhaitez déboguer le programme **depuis son lancement** :

```sh
gdbserver :1234 ./programme
```

Soit vous préférez le déboguer alors qu'il est **en cours d'exécution** :

```sh
gdbserver :1234 --attach PID_PROGRAMME
```

Où `PID_PROGRAMME` est le PID du challenge.

Enfin, il suffit d'ouvrir **gdb** en dehors du conteneur et d'exécuter :

```
target remote 127.0.0.1:1234
```

> Dans la plupart des cas `target remote :1234` fonctionne aussi.
{: .prompt-tip }

> Si **gdb** ne se connecte pas une fois la commande exécutée, il y a probablement un problème au niveau de l'adresse ou du port utilisé. Dans ce cas il faudra adapter la précédente commande à votre configuration.
{: .prompt-warning }

## ⛔ Signaler un problème

Si tu as trouvé un **problème** lors de la **mise en place** ou de la **résolution** d'un challenge, n'hésite pas à nous envoyer un mail à `reverse_zip[aro b ase]proton.me`.