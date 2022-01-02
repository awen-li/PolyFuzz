

#include "pcgInstrm.h"


int main (int argc, char *argv[])
{
    /* new CFG */
    pcgCFGAlloct (1);

    /* Insert EDGEs */
    pcgCFGEdge(1, 2);
    pcgCFGEdge(2, 4);
    pcgCFGEdge(4, 5);
    pcgCFGEdge(5, 7);
    pcgCFGEdge(1, 3);
    pcgCFGEdge(3, 5);
    pcgCFGEdge(3, 6);
    pcgCFGEdge(6, 7);

    /* build */
    pcgBuild();

    return 0;
}

