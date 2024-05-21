package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

/**
 * <p>Provides operations for the Privilege entity to interact with a database.</p>
 * @see Privilege
 */

@Repository
public interface PrivilegeRepository extends JpaRepository<Privilege, UUID> {

    Privilege findByName(String name);

}