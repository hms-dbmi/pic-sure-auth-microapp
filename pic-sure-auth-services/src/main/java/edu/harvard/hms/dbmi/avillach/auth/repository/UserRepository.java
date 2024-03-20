package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.entity.Connection;
import edu.harvard.hms.dbmi.avillach.auth.entity.Role;
import edu.harvard.hms.dbmi.avillach.auth.entity.TermsOfService;
import edu.harvard.hms.dbmi.avillach.auth.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import javax.persistence.NoResultException;
import javax.persistence.NonUniqueResultException;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import javax.persistence.criteria.Subquery;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * <p>Provides operations for the User entity to interact with a database.</p>
 * @see User
 */

@Repository
public class UserRepository extends BaseRepository<User, UUID> {

	private final static Logger logger = LoggerFactory.getLogger(UserRepository.class);

	protected UserRepository() {
		super(User.class);
	}

	public User findBySubject(String subject) {
		CriteriaQuery<User> query = em.getCriteriaBuilder().createQuery(User.class);
		Root<User> queryRoot = query.from(User.class);
		query.select(queryRoot);
		CriteriaBuilder cb = cb();
		return em.createQuery(query
				.where(
						eq(cb, queryRoot, "subject", subject)))
				.getSingleResult();
	}

	public User findBySubjectAndConnection(String subject, String connectionId){
		CriteriaQuery<User> query = em.getCriteriaBuilder().createQuery(User.class);
		Root<User> queryRoot = query.from(User.class);
		query.select(queryRoot);
		CriteriaBuilder cb = cb();
		try {
            return em.createQuery(query
                    .where(
                            cb.and(
									cb.equal(queryRoot.join("connection")
											.get("id"), connectionId),
                                    eq(cb, queryRoot, "subject", subject))))
                    .getSingleResult();
        } catch (NoResultException e){
		    return null;
        }
	}

	public List<User> listUnmatchedByConnectionId(Connection connection) {
		CriteriaQuery<User> query = em.getCriteriaBuilder().createQuery(User.class);
		Root<User> queryRoot = query.from(User.class);
		query.select(queryRoot);
		CriteriaBuilder cb = cb();
		return em.createQuery(query
				.where(
						cb.and(
								eq(cb, queryRoot, "connection", connection),
								eq(cb, queryRoot, "matched", false))))
				.getResultList();
	}

	/**
	 *
	 * @return
	 */
	public User findOrCreate(User inputUser) {
		User user = null;
		String subject = inputUser.getSubject();
		try{
			user = findBySubject(subject);
			logger.info("findOrCreate(), trying to find user: {subject: " + subject+
					"}, and found a user with uuid: " + user.getUuid()
					+ ", subject: " + user.getSubject());
		} catch (NoResultException e) {
			logger.debug("findOrCreate() subject " + subject +
					" could not be found by `entityManager`, going to create a new user.");
			user = createUser(inputUser);
		}catch(NonUniqueResultException e){
			logger.error("findOrCreate() " + e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		return user;
	}

	private User createUser(User inputUser) {
		String subject = inputUser.getSubject();
		logger.debug("createUser() creating user, subject: " + subject + " ......");
		em().persist(inputUser);

		User result = getById(inputUser.getUuid());
		if (result != null)
			logger.info("createUser() created user, uuid: " + result.getUuid()
					+ ", subject: " + subject
					+ ", role: " + result.getRoleString()
					+ ", privilege: "+ result.getPrivilegeString());

		return result;
	}

	public User changeRole(User user, Set<Role> roles){
		logger.info("Starting changing the role of user: " + user.getUuid()
				+ ", with subject: " + user.getSubject() + ", to " + roles.stream().map(role -> role.getName()).collect(Collectors.joining(",")));
		user.setRoles(roles);
		em().merge(user);
		User updatedUser = getById(user.getUuid());
		logger.info("User: " + updatedUser.getUuid() + ", with subject: " +
				updatedUser.getSubject() + ", now has a new role: " + updatedUser.getRoleString());
		return updatedUser;
	}

	@Override
	public void persist(User user) {
		findOrCreate(user);
	}

	public User findByEmail(String email) {
		CriteriaQuery<User> query = em.getCriteriaBuilder().createQuery(User.class);
		Root<User> queryRoot = query.from(User.class);
		query.select(queryRoot);
		CriteriaBuilder cb = cb();
		return em.createQuery(query
				.where(
						eq(cb, queryRoot, "email", email)))
				.getSingleResult();
	}

	public boolean checkAgainstTOSDate(String userId){
		CriteriaQuery<User> query = cb().createQuery(User.class);
		Root<User> queryRoot = query.from(User.class);
		query.select(queryRoot);
		CriteriaBuilder cb = cb();

		Subquery<Date> subquery = query.subquery(Date.class);
		Root<TermsOfService> tosRoot = subquery.from(TermsOfService.class);
		subquery.select(cb.greatest(tosRoot.<Date>get("dateUpdated")));

		return !em.createQuery(query
				.where(
						cb.and(
								eq(cb, queryRoot, "subject", userId),
								cb.greaterThanOrEqualTo(queryRoot.get("acceptedTOS"), subquery))))
				.getResultList().isEmpty();
	}

}
