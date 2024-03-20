package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * <p>Provides operations for the Role entity to interact with a database.</p>
 * @see Role
 */

@Repository
public class RoleRepository extends BaseRepository<Role, UUID> {

    protected RoleRepository() {
        super(Role.class);
    }
}
