
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "pcgInstrm.h"

void Test1 ()
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

    assert (pcgIsDominated(2, 4) == true);
    assert (pcgIsDominated(3, 6) == true);
    assert (pcgIsDominated(1, 2) == true);
    assert (pcgIsDominated(1, 3) == true);

    assert (pcgIsPostDominated(5, 4) == true);
    assert (pcgIsPostDominated(4, 2) == true);
    assert (pcgIsPostDominated(5, 2) == true);
}

void Test2 ()
{
    /* new CFG */
    pcgCFGAlloct (1);

    /* Insert EDGEs */
    pcgCFGEdge(1, 2);
    pcgCFGEdge(1, 3);
    pcgCFGEdge(1, 4);
    pcgCFGEdge(1, 5);
    
    pcgCFGEdge(5, 6);
    pcgCFGEdge(2, 7);
    pcgCFGEdge(3, 7);
    pcgCFGEdge(4, 7);

    pcgCFGEdge(6, 8);
    pcgCFGEdge(7, 8);

    /* build */
    pcgBuild();

    assert (pcgIsDominated(5, 6) == true);

    assert (pcgIsPostDominated(7, 2) == true);
    assert (pcgIsPostDominated(7, 3) == true);
    assert (pcgIsPostDominated(7, 4) == true);
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

