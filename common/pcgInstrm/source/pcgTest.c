
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "pcgInstrm.h"

void Test1 ()
{
    /* new CFG */
    unsigned Hd = pcgCFGAlloct (1);

    /* Insert EDGEs */
    pcgCFGEdge(Hd, 1, 2);
    pcgCFGEdge(Hd, 2, 4);
    pcgCFGEdge(Hd, 4, 5);
    pcgCFGEdge(Hd, 5, 7);
    pcgCFGEdge(Hd, 1, 3);
    pcgCFGEdge(Hd, 3, 5);
    pcgCFGEdge(Hd, 3, 6);
    pcgCFGEdge(Hd, 6, 7);

    /* build */
    pcgBuild(Hd);

    assert (pcgIsDominated(Hd, 2, 4) == true);
    assert (pcgIsDominated(Hd, 3, 6) == true);
    assert (pcgIsDominated(Hd, 1, 2) == true);
    assert (pcgIsDominated(Hd, 1, 3) == true);

    assert (pcgIsPostDominated(Hd, 5, 4) == true);
    assert (pcgIsPostDominated(Hd, 4, 2) == true);
    assert (pcgIsPostDominated(Hd, 5, 2) == true);

    pcgCFGDel (Hd);
}

void Test2 ()
{
    /* new CFG */
    unsigned Hd = pcgCFGAlloct (1);

    /* Insert EDGEs */
    pcgCFGEdge(Hd, 1, 2);
    pcgCFGEdge(Hd, 1, 3);
    pcgCFGEdge(Hd, 1, 4);
    pcgCFGEdge(Hd, 1, 5);
    
    pcgCFGEdge(Hd, 5, 6);
    pcgCFGEdge(Hd, 2, 7);
    pcgCFGEdge(Hd, 3, 7);
    pcgCFGEdge(Hd, 4, 7);

    pcgCFGEdge(Hd, 6, 8);
    pcgCFGEdge(Hd, 7, 8);

    /* build */
    pcgBuild(Hd);

    assert (pcgIsDominated(Hd, 5, 6) == true);

    assert (pcgIsPostDominated(Hd, 7, 2) == true);
    assert (pcgIsPostDominated(Hd, 7, 3) == true);
    assert (pcgIsPostDominated(Hd, 7, 4) == true);

    pcgCFGDel (Hd);
}



int main (int argc, char *argv[])
{
    printf ("********************** Test1 ********************** \r\n");
    Test1 ();
    printf ("*************************************************** \r\n\r\n");

    printf ("********************** Test2 ********************** \r\n");
    Test2 ();
    printf ("*************************************************** \r\n\r\n");

    return 0;
}

