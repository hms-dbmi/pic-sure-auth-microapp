package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * <p>Provides operations for the AccessRule entity to interact with a database.</p>
 *
 * @see AccessRule
 */
@Repository
public class AccessRuleRepository extends BaseRepository<AccessRule, UUID> {

    protected AccessRuleRepository() {
        super(AccessRule.class);
    }
}
