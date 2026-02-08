NAMESPACE Motors
    CLASS BasicMotor
        VAR
            status : BOOL;
        END_VAR

        METHOD PUBLIC Start : BOOL
            status := TRUE;
        END_METHOD

        METHOD PUBLIC Stop : BOOL
            status := FALSE;
        END_METHOD

        METHOD PUBLIC IsRunning : BOOL
            isRunning := status;
        END_METHOD
    END_CLASS

END_NAMESPACE