(() => {
 const values=new URLSearchParams(location.hash.slice(1)),form=document.querySelector('[data-recovery-enrollment]');
 if(!form||!values.has('caseId')||!values.has('token'))return;
 form.elements.namedItem('caseId').value=values.get('caseId');
 form.elements.namedItem('token').value=values.get('token');
 history.replaceState(null,'',location.pathname+location.search);
 form.scrollIntoView();
})();
