#include <stdio.h>

typedef struct functable_t {
    void (*toString)(void*);
} FuncTable;

typedef struct a_t {
    FuncTable* vtable;
    char* name;
} A;

typedef struct b_t {
    FuncTable* vtable;
    char* name;
} B;


void toString_A(void* obj)
{
    A* a_obj = (A*)obj;

    printf("A object: %p\n", obj);
    printf("A name: %s\n", a_obj->name);
}

void toString_B(void* obj)
{
    B* b_obj = (B*)obj;

    printf("B object: %p\n", obj);
    printf("B name: %s\n", b_obj->name);
}

FuncTable a_vtbl = {
    toString_A
};

FuncTable b_vtbl = {
    toString_B
};

int main(int argc, char** argv)
{
    A a_obj;
    a_obj.name = "AAAAAAAAAAAAAH!!!";
    a_obj.vtable = &a_vtbl;

    B b_obj;
    b_obj.name = "BBBBBBBBBBBBRRRR!!!";
    b_obj.vtable = &b_vtbl;

    a_obj.vtable->toString(&a_obj);
    b_obj.vtable->toString(&b_obj);

    return 0;
}
