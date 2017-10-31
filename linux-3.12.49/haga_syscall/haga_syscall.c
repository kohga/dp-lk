#include <linux/kernel.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE2( haga_syscall, char __user *, buf, int, count )
{
	long err;
    char text[ ] = "haga syscall!";

    printk( "<HAGA_SYSCALL>%s\n", text );

    if( count < sizeof( text ) )
    {
        return( -ENOMEM );
    }

    /* copy untill null terminator */
    err = copy_to_user( buf, text, sizeof( text ) );
    	
    return( err );
}
