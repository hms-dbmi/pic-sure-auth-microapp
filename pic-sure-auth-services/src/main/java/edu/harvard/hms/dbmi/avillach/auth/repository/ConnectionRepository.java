package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import org.springframework.stereotype.Repository;

import javax.persistence.NoResultException;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.util.UUID;

/**
 * <p>Provides operations for the Connection entity to interact with a database.</p>
 *
 * @see Connection
 */
@Repository
public class ConnectionRepository extends BaseRepository<Connection, UUID> {

    protected ConnectionRepository() {
        super(Connection.class);
    }

    public Connection findConnectionById(String connectionId) {
        CriteriaQuery<Connection> query = em.getCriteriaBuilder().createQuery(Connection.class);
        Root<Connection> queryRoot = query.from(Connection.class);
        query.select(queryRoot);
        CriteriaBuilder cb = cb();
        try {
            return em.createQuery(query
                            .where(
                                    eq(cb, queryRoot, "id", connectionId)))
                    .getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }
}
