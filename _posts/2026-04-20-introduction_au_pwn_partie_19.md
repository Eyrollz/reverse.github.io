---
title: Partie 19 - 🏆 Challenge - exploitation complète des format strings (5/5)
date: 2026-04-20 10:00:00
categories: [Pwn, Introduction au pwn]
tags: [x86, pwn, linux]     # TAG names should always be lowercase
author: kabeche
toc: true
---

# 🏆 Challenge : exploitation complète des *format strings* (5/5)

Comme à l'accoutumée, c'est l'heure du du du du challenge !

Le programme à exploiter est très basique. Pas besoin d'y passer des heures à l'analyser. De même que la phase d'exploitation ne devrait pas être trop compliquée. 

C'est l'occasion de réaliser une chose dont nous n'avons pas parlé dans les précédents chapitres : **comment ouvrir un terminal en exploitant une vulnérabilité dans une chaîne de format** ? 

C'est aussi l'occasion d'essayer de comprendre les choses **par vous-mêmes**. Toujours est-il que si vous ne voyez pas de quelle technique il s'agit ou que vous êtes **totalement bloqués**, n'hésitez pas à jeter un œil aux indices.

- ⬇️ **Téléchargement** : [pwn-fmt-challenge.zip](https://drive.proton.me/urls/N14CRCXZV8#SyydAjYNdPBR)
- 🔎 **SHA256 & Analyse Virus Total** : [9e7411a01b95dad0738cf802454f5c55cf4357f3756d286bec92308dc1ec7735](https://www.virustotal.com/gui/file/9e7411a01b95dad0738cf802454f5c55cf4357f3756d286bec92308dc1ec7735)
- 🎯 **Objectif** : réussir à ouvrir un terminal (pas obligatoirement `root`).

## 💻 Contexte d'exécution

Afin de se placer dans le contexte d'exécution prévu pour ce exercice, il est nécessaire :

- d'activer l'**ASLR** ;
- d'atteindre l'objectif **en dehors** d'un **déboggeur**.

## 💫 Lancer le challenge

Ci-dessous les commandes permettant de lancer le challenge :

- **construction du conteneur** : `docker build -t pwn-fmt-challenge .`;
- **lancement du conteneur et du challenge**  : 

```sh
docker run -it --rm -p 1234:1234 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined pwn-fmt-challenge
```

Le **port** accessible est le suivant :

- `1234` : port qu'il est possible d'utiliser pour déboguer à distance avec `gdbserver`.

## 💡 Indices

Voici quelques indices qui devraient vous permettre d'avancer lorsque vous êtes bloqués et que vous ne voyez pas comment aller plus loin.

#### 💡 **Indice n°1**

```
LSBRdWVsbGVzIHNvbnQgbGVzIHByb3RlY3Rpb25zIHByw6lzZW50ZXMgPyAuLi4gb3Ugbm9uID8gUXUnaW1wbGlxdWUgbGV1ciBwcsOpc2VuY2Ugb3UgYWJzZW5jZSA/Ci0gUXVlbGxlIGVzdCBsZSBwcmVtaWVyIHByb2Jsw6htZSDDoCByw6lzb3VkcmUgYWZpbiBkJ2F2b2lyIHBsdXMgZGUgbWFyZ2UgZGUgbWFuxZN1dnJlLg==
```

#### 💡 **Indice n°2**

```
RW4gYXlhbnQgc2V1bGVtZW50IHVuZSB0ZW50YXRpdmUgYXZlYyBsYSBjaGHDrm5lIGRlIGZvcm1hdCBub3VzIG5lIHBvdXJyb25zIHBhcyBhbGxlciB0csOocyBsb2luLiBDb21tZW50IGZhaXJlIHBvdXIgcmVsYW5jZXIgbGEgbGVjdHVyZSBldCB1dGlsaXNhdGlvbiBkZSBub3RyZSBjaGHDrm5lIGRlIGZvcm1hdCA/
```

#### 💡 **Indice n°3**

```
U2NvIHBhIHR1IG1hbmFhCgpgYGAKICAgIEFyY2g6ICAgICBpMzg2LTMyLWxpdHRsZQogICAgUkVMUk86ICAgIFBhcnRpYWwgUkVMUk8gPC0tLS0gPwogICAgU3RhY2s6ICAgIENhbmFyeSBmb3VuZAogICAgTlg6ICAgICAgIE5YIGVuYWJsZWQKICAgIFBJRTogICAgICBObyBQSUUgKDB4ODA0ODAwMCkKYGBg
```

#### 💡 **Indice n°4**

```
U2kgdm91cyBuJ2F2ZXogcGFzIHRyb3V2w6kgY29tbWVudCBsJ2V4cGxvaXRlciwgbuKAmWjDqXNpdGV6IHBhcyBhIGpldGVyIHVuIMWTaWwgYXUgY2hhcGl0cmUgZMOpZGnDqSBhdXggcmVsb2NhbGlzYXRpb25zIC8gR09UIC9QTFQgOyk=
```

#### 💡 **Indice n°5**

```
UXUnZXN0LWNlIHF1aSBub3VzIGVtcMOqY2hlIGRlIHJlbnRyZXIgcGx1c2lldXJzIGZvaXMgZGFucyBsYSBmb25jdGlvbiAibWFpbiIgPw==
```








