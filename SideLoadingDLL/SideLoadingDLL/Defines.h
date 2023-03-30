#pragma once
#include "windows.h"

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
		(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
		(p)->RootDirectory = r;                           \
		(p)->Attributes = a;                              \
		(p)->ObjectName = n;                              \
		(p)->SecurityDescriptor = s;                      \
		(p)->SecurityQualityOfService = NULL;             \
		}