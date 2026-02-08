CONFIGURATION MyConfiguration
    TASK Main(Priority := 1);
    
    PROGRAM P1 WITH Main: MainProgram;
        
    VAR_GLOBAL
        startmotor: BOOL;
        stopmotor: BOOL;
    END_VAR
END_CONFIGURATION