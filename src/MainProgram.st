USING Motors;

PROGRAM MainProgram
    VAR_EXTERNAL
        startmotor: BOOL;
        stopmotor: BOOL;
    END_VAR
    
    VAR
        motorA : BasicMotor;
    END_VAR

    IF startmotor THEN
        motorA.Start();
    END_IF;

END_PROGRAM