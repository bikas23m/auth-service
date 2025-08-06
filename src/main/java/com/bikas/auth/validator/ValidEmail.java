package com.bikas.auth.validator;

import java.lang.annotation.*;

/**
 * Annotation for email validation
 */
@Documented
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
@jakarta.validation.Constraint(validatedBy = EmailValidator.class)
@interface ValidEmail {
    String message() default "Invalid email address";
    Class<?>[] groups() default {};
    Class<? extends jakarta.validation.Payload>[] payload() default {};
    boolean allowDisposable() default false;
}
