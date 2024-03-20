package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * <p>Provides operations for the Privilege entity to interact with a database.</p>
 * @see Privilege
 */

@Repository
public class PrivilegeRepository extends BaseRepository<Privilege, UUID> {

    protected PrivilegeRepository() {
        super(Privilege.class);
    }
}
