import {nativePerson} from './native-person.mjs';

/** The real signed claim, Auth email proof and native passkey lifecycle. */
export default async function initialize({reviewers,...options}) {
 const owner=await nativePerson(options);
 const invited=await owner.call('/api/auth/people/invite',{email:'agent-worker@example.com',name:'Morgan Worker'});
 if(invited.status!==201)throw new Error('Native worker invitation refused');
 await reviewers.initialize('worker',{cookie:owner.cookie()});
 return owner.response;
}
