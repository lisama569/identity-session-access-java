package com.github.lisama569.identitysessionaccessjava.auth.policy;

import com.github.lisama569.identitysessionaccessjava.auth.model.AccessRequest;
import com.github.lisama569.identitysessionaccessjava.auth.model.Principal;

/** ABAC 属性条件：对主体属性与资源属性做匹配。 */
@FunctionalInterface
public interface AttributeCondition {

    boolean test(Principal subject, AccessRequest request);

    default String describe() {
        return "attribute-condition";
    }
}
