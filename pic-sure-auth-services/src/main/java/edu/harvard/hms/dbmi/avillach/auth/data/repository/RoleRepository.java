package edu.harvard.hms.dbmi.avillach.auth.data.repository;

import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.data.entity.Role;

import javax.enterprise.context.ApplicationScoped;
import javax.transaction.Transactional;
import java.util.*;

/**
 * <p>Provides operations for the Role entity to interact with a database.</p>
 * @see Role
 */
@ApplicationScoped
@Transactional
public class RoleRepository extends BaseRepository<Role, UUID> {

    protected RoleRepository() {
        super(Role.class);
    }

    /**
     * Persists all roles in the list to the database. This method is used to batch insert roles.
     * @param roles the list of roles to be inserted
     */
    public void persistAll(Collection<Role> roles) {
        int batchSize = 20; // Adjust batch size as necessary
        int i = 0;
        for (Role role : roles) {
            em.persist(role);
            if (i % batchSize == 0 && i > 0) {
                em.flush();
            }
            i++;
        }

        em.flush();
    }

    public Set<Role> getRolesByNames(Set<String> rolesThatExist) {
        return new HashSet<>(em.createQuery("SELECT r FROM role r WHERE r.name IN :rolesThatExist", Role.class)
                .setParameter("rolesThatExist", rolesThatExist)
                .getResultList());
    }
}
