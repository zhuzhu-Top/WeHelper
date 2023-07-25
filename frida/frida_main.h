//
// Created by 28264 on 2023/5/22.
//

#ifndef WEHELPER_FRIDA_MAIN_H
#define WEHELPER_FRIDA_MAIN_H



void FridaMain();

#include "pub_include.h"

#include "core.h"
#include "frida-core.h"


static void on_detached (FridaSession * session, FridaSessionDetachReason reason, FridaCrash * crash, gpointer user_data);
static void on_signal (int signo);
static gboolean stop (gpointer user_data);

static GMainLoop * loop = NULL;

#endif //WEHELPER_FRIDA_MAIN_H
