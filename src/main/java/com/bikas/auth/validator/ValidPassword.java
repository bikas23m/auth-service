package com.bikas.auth.validator;

import java.lang.annotation.*;

/**
 * Annotation for password validation
 */
@Documented
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@jakarta.validation.Constraint(validatedBy =
        PasswordValidator.class)
@interface ValidPassword {
    String message() default "Invalid password";
    Class<?>[] groups() default {};
    Class<? extends jakarta.validation.Payload>[] payload() default {};
}