package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.hms.dbmi.avillach.auth.entity.AccessRule;
import edu.harvard.hms.dbmi.avillach.auth.entity.Privilege;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * <p>Provides operations for the Privilege entity to interact with a database.</p>
 * @see Privilege
 */

@Repository
public interface PrivilegeRepository extends JpaRepository<Privilege, UUID> {

    Privilege findByName(String name);



    @Modifying
    @Query("UPDATE access_rule ar SET ar.subAccessRule = :subRules WHERE ar.uuid = :uuid")
    void addSubAccessRuleToPrivilege(@Param("uuid") UUID uuid, @Param("subRules") Set<AccessRule> subRules);

}
